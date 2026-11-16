"""Immutable AuditLog ORM model (DATABASE_SCHEMA.md Section 2.1)."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonVariant, utc_now

if TYPE_CHECKING:
    from app.models.user import Organization


class AuditLog(Base):
    """Immutable audit record for security-sensitive actions and scope attestations."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(60), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="audit_logs"
    )
