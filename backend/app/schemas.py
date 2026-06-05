from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    alert_id: str | None = None
    title: str
    severity: str = "High"
    category: str
    source: str | None = None
    timestamp: str | None = None
    affected_asset: str
    affected_user: str | None = None
    owner_team: str | None = None
    owner_email: str | None = None
    description: str | None = None
    ioc_list: str | None = None
    raw_log: str | None = None
    process_tree: str | None = None
    timeline_logs: str | None = None
    status: str = "pending"
    notes: str | None = None
    tags: str | None = None
    validation_json: str | None = None


class AlertUpdate(BaseModel):
    title: str | None = None
    severity: str | None = None
    category: str | None = None
    source: str | None = None
    timestamp: str | None = None
    affected_asset: str | None = None
    affected_user: str | None = None
    owner_team: str | None = None
    owner_email: str | None = None
    description: str | None = None
    ioc_list: str | None = None
    raw_log: str | None = None
    process_tree: str | None = None
    timeline_logs: str | None = None
    status: str | None = None
    notes: str | None = None
    tags: str | None = None
    validation_json: str | None = None


class AlertOut(BaseModel):
    id: str
    alert_id: str
    title: str
    severity: str
    category: str
    source: str | None
    timestamp: str | None
    affected_asset: str
    affected_user: str | None
    owner_team: str | None
    owner_email: str | None
    description: str | None
    ioc_list: str | None
    raw_log: str | None
    process_tree: str | None
    timeline_logs: str | None
    status: str
    notes: str | None
    tags: str | None
    validation_json: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AgentMessage(BaseModel):
    role: Literal["system", "agent", "tool", "result"]
    content: str
    ts: datetime | str | None = None


class InvestigationOut(BaseModel):
    id: str
    alert_id: str
    status: str
    progress_pct: int
    current_step: str | None
    messages: list[AgentMessage]
    report_markdown: str | None
    error: str | None
    ai_used: bool
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class SettingsOut(BaseModel):
    ai_enabled: bool
    ai_provider: str
    ai_model: str
    api_base_url: str | None
    has_api_key: bool


class SettingsUpdate(BaseModel):
    ai_enabled: bool | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    api_base_url: str | None = None
    api_key: str | None = None
    clear_api_key: bool = False


class AlertMatchOut(BaseModel):
    id: str
    alert_id: str
    matched_alert_id: str
    score: int
    details_json: str
    created_at: datetime
    matched_alert_title: str | None = None
    matched_alert_status: str | None = None

    model_config = {"from_attributes": True}


class TriageLikelihood(BaseModel):
    tp_probability: int
    fp_probability: int
    assessment: str   # 'likely_tp' | 'likely_fp' | 'uncertain' | 'new_threat'
    reason: str
    total_matches: int
    tp_matches: int
    fp_matches: int
