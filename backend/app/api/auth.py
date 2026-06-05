import os
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional
import jwt
import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import User

router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer()

JWT_SECRET = get_settings().secret_key
JWT_ALGORITHM = "HS256"

# Password Hashing
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    db_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return f"{salt.hex()}:{db_hash.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt_hex, hash_hex = hashed.split(":")
        salt = bytes.fromhex(salt_hex)
        db_hash = bytes.fromhex(hash_hex)
        check_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return check_hash == db_hash
    except Exception:
        return False


# JWT Helpers
def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=1)
    payload = {
        "sub": user_id,
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_temp_mfa_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "sub": user_id,
        "exp": int(expire.timestamp()),
        "type": "mfa_pending"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_temp_mfa_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") == "mfa_pending":
            return payload.get("sub")
    except jwt.PyJWTError:
        pass
    return None


# Authentication Dependency
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
        )
        
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


# Schemas
class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class VerifyMfaRequest(BaseModel):
    temp_token: str
    code: str


class VerifyCodeRequest(BaseModel):
    code: str


# Endpoints
@router.get("/status")
async def get_auth_status(db: AsyncSession = Depends(get_db)):
    """Check if any users are registered in the DB."""
    result = await db.execute(select(User))
    users = result.scalars().all()
    return {"has_users": len(users) > 0}


@router.post("/register")
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user."""
    # Check if user already exists
    result = await db.execute(select(User).where(User.username == payload.username.strip()))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user = User(
        username=payload.username.strip(),
        password_hash=hash_password(payload.password),
        mfa_enabled=False
    )
    db.add(user)
    await db.commit()
    return {"ok": True, "message": "User registered successfully"}


@router.post("/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Login with credentials, returning temporary token if MFA is enabled."""
    result = await db.execute(select(User).where(User.username == payload.username.strip()))
    user = result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    if user.mfa_enabled:
        temp_token = create_temp_mfa_token(user.id)
        return {"mfa_required": True, "temp_token": temp_token}
    
    access_token = create_access_token(user.id)
    return {"mfa_required": False, "access_token": access_token, "token_type": "bearer"}


@router.post("/verify-mfa")
async def verify_mfa(payload: VerifyMfaRequest, db: AsyncSession = Depends(get_db)):
    """Verify MFA code using temporary token and generate access token."""
    user_id = verify_temp_mfa_token(payload.temp_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired temporary token")
        
    user = await db.get(User, user_id)
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA is not set up for this user")
        
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.code.strip(), valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid verification code")
        
    access_token = create_access_token(user.id)
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/setup-mfa")
async def setup_mfa(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Provision a new TOTP key."""
    # Generate secret if not already set, or generate a fresh one if MFA is not enabled yet
    if not user.mfa_enabled or not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        await db.commit()
        await db.refresh(user)
        
    totp = pyotp.TOTP(user.mfa_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="SOC Triage Tool")
    return {
        "mfa_secret": user.mfa_secret,
        "provisioning_uri": uri
    }


@router.post("/enable-mfa")
async def enable_mfa(payload: VerifyCodeRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Enable MFA for the user after validating a code generated from the secret."""
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA has not been set up. Call setup-mfa first.")
        
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(payload.code.strip(), valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid verification code. Could not enable MFA.")
        
    user.mfa_enabled = True
    await db.commit()
    return {"ok": True, "message": "MFA enabled successfully"}


@router.post("/disable-mfa")
async def disable_mfa(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Disable MFA."""
    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()
    return {"ok": True, "message": "MFA disabled successfully"}


@router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    """Get current user information."""
    return {
        "id": user.id,
        "username": user.username,
        "mfa_enabled": user.mfa_enabled
    }
