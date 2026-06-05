from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto_util import decrypt_secret, encrypt_secret
from app.database import get_db
from app.models import AppSettings, utcnow
from app.schemas import SettingsOut, SettingsUpdate
from app.api.auth import get_current_user

router = APIRouter(
    prefix="/api/settings",
    tags=["settings"],
    dependencies=[Depends(get_current_user)]
)


async def _get_or_create(db: AsyncSession) -> AppSettings:
    row = await db.get(AppSettings, 1)
    if not row:
        row = AppSettings(id=1)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


@router.get("", response_model=SettingsOut)
async def get_settings(db: AsyncSession = Depends(get_db)):
    row = await _get_or_create(db)
    return SettingsOut(
        ai_enabled=row.ai_enabled,
        ai_provider=row.ai_provider,
        ai_model=row.ai_model,
        api_base_url=row.api_base_url,
        has_api_key=bool(row.api_key_encrypted),
    )


@router.put("", response_model=SettingsOut)
async def update_settings(payload: SettingsUpdate, db: AsyncSession = Depends(get_db)):
    row = await _get_or_create(db)
    if payload.ai_enabled is not None:
        row.ai_enabled = payload.ai_enabled
    if payload.ai_provider is not None:
        row.ai_provider = payload.ai_provider
    if payload.ai_model is not None:
        row.ai_model = payload.ai_model
    if payload.api_base_url is not None:
        row.api_base_url = payload.api_base_url or None
    if payload.clear_api_key:
        row.api_key_encrypted = None
    if payload.api_key:
        row.api_key_encrypted = encrypt_secret(payload.api_key.strip())
    row.updated_at = utcnow()
    await db.commit()
    await db.refresh(row)
    return SettingsOut(
        ai_enabled=row.ai_enabled,
        ai_provider=row.ai_provider,
        ai_model=row.ai_model,
        api_base_url=row.api_base_url,
        has_api_key=bool(row.api_key_encrypted),
    )


@router.post("/test-key")
async def test_api_key(db: AsyncSession = Depends(get_db)):
    """Validate stored API key with a minimal request when AI is enabled."""
    row = await _get_or_create(db)
    if not row.api_key_encrypted:
        return {"ok": False, "message": "No API key stored"}
    if not row.ai_enabled:
        return {"ok": False, "message": "AI is disabled — enable in settings first"}
    try:
        from app.services.ai_providers import complete_investigation

        key = decrypt_secret(row.api_key_encrypted)
        await complete_investigation(
            provider=row.ai_provider,
            model=row.ai_model,
            api_key=key,
            base_url=row.api_base_url,
            system_prompt="You are a test assistant.",
            user_prompt="Reply with exactly: OK",
        )
        return {"ok": True, "message": "API key accepted"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
