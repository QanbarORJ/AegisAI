"""Organization and User ORM models (DATABASE_SCHEMA.md Section 2.1)."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.security import RoleEnum
from app.db.base import Base, utc_now

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.audit import AuditLog
    from app.models.target import TargetProfile


class Organization(Base):
    """Multi-tenant organization boundary."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    max_rps_limit: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    users: Mapped[list["User"]] = relationship(
        "User", back_populates="organization", cascade="all, delete-orphan"
    )
    target_profiles: Mapped[list["TargetProfile"]] = relationship(
        "TargetProfile", back_populates="organization", cascade="all, delete-orphan"
    )
    assessments: Mapped[list["Assessment"]] = relationship(
        "Assessment", back_populates="organization", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="organization", cascade="all, delete-orphan"
    )


class User(Base):
    """Platform user belonging to an Organization with a specific RBAC role."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(40), default=RoleEnum.SECURITY_ENGINEER.value, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="users"
    )
