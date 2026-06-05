import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Investigation
from app.schemas import AgentMessage, InvestigationOut
from app.api.auth import get_current_user

router = APIRouter(
    prefix="/api/investigations",
    tags=["investigations"],
    dependencies=[Depends(get_current_user)]
)


def _inv_to_out(inv: Investigation) -> InvestigationOut:
    messages = json.loads(inv.messages_json or "[]")
    return InvestigationOut(
        id=inv.id,
        alert_id=inv.alert_id,
        status=inv.status,
        progress_pct=inv.progress_pct,
        current_step=inv.current_step,
        messages=[AgentMessage(**m) for m in messages],
        report_markdown=inv.report_markdown,
        error=inv.error,
        ai_used=inv.ai_used,
        started_at=inv.started_at,
        completed_at=inv.completed_at,
        created_at=inv.created_at,
    )


@router.get("/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(investigation_id: str, db: AsyncSession = Depends(get_db)):
    inv = await db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return _inv_to_out(inv)
