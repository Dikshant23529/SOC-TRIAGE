import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), default="High")
    category: Mapped[str] = mapped_column(String(128))
    source: Mapped[str | None] = mapped_column(String(256), nullable=True)
    timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    affected_asset: Mapped[str] = mapped_column(String(256))
    affected_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    owner_team: Mapped[str | None] = mapped_column(String(256), nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    ioc_list: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    process_tree: Mapped[str | None] = mapped_column(Text, nullable=True)
    timeline_logs: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(String(512), nullable=True)
    validation_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )
    matches: Mapped[list["AlertMatch"]] = relationship(
        "AlertMatch",
        primaryjoin="Alert.id == AlertMatch.alert_id",
        cascade="all, delete-orphan",
        back_populates="alert"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    current_step: Mapped[str | None] = mapped_column(String(256), nullable=True)
    messages_json: Mapped[str] = mapped_column(Text, default="[]")
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_used: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    alert: Mapped["Alert"] = relationship(back_populates="investigations")


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    ai_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_provider: Mapped[str] = mapped_column(String(64), default="openai")
    ai_model: Mapped[str] = mapped_column(String(128), default="gpt-4o-mini")
    api_base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    mfa_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertMatch(Base):
    __tablename__ = "alert_matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"), index=True)
    matched_alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id"))
    score: Mapped[int] = mapped_column(Integer)  # Matching percentage (0-100)
    details_json: Mapped[str] = mapped_column(Text, default="{}")  # Breakdown of similarities
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", foreign_keys=[alert_id], back_populates="matches")
    matched_alert: Mapped["Alert"] = relationship("Alert", foreign_keys=[matched_alert_id])
