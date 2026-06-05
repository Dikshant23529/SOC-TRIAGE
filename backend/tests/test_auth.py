import pytest
import jwt
from datetime import timedelta
from app.api.auth import hash_password, verify_password, create_access_token, create_temp_mfa_token, verify_temp_mfa_token


def test_password_hashing():
    password = "SuperSecretPassword123"
    hashed = hash_password(password)
    
    assert hashed != password
    assert ":" in hashed
    
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False
    assert verify_password(password, "malformedhash") is False


def test_jwt_access_tokens():
    user_id = "user-123-abc"
    token = create_access_token(user_id, expires_delta=timedelta(minutes=10))
    
    assert token is not None
    assert isinstance(token, str)
    
    # Verify we can decode it and retrieve sub
    from app.api.auth import JWT_SECRET, JWT_ALGORITHM
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert payload["sub"] == user_id


def test_temp_mfa_tokens():
    user_id = "user-789-xyz"
    temp_token = create_temp_mfa_token(user_id)
    
    assert temp_token is not None
    
    decoded_user = verify_temp_mfa_token(temp_token)
    assert decoded_user == user_id
    
    # Invalid token check
    assert verify_temp_mfa_token("invalid.token.here") is None
