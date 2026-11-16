"""Assessment ORM model and canonical lifecycle state enum (DATABASE_SCHEMA.md Section 2.3)."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonVariant, utc_now

if TYPE_CHECKING:
    from app.models.finding import Finding, TestExecutionResult
    from app.models.target import TargetProfile
    from app.models.user import Organization


class AssessmentStatusEnum(StrEnum):
    """Canonical 8-state assessment lifecycle standardized across AegisAI."""

    DRAFT = "DRAFT"
    QUEUED = "QUEUED"
    PROFILING = "PROFILING"
    ANALYZING_ARCHITECTURE = "ANALYZING_ARCHITECTURE"
    EXECUTING_TESTS = "EXECUTING_TESTS"
    EVALUATING = "EVALUATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Assessment(Base):
    """Security assessment run bound to a TargetProfile and an explicit ScopeAttestation."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("target_profiles.id", ondelete="CASCADE"), index=True, nullable=False
    )
    initiated_by_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    selected_modules: Mapped[list[str]] = mapped_column(
        JsonVariant, default=list, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(40), default=AssessmentStatusEnum.DRAFT.value, index=True, nullable=False
    )
    scope_attestation: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    target_profile_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    progress_pct: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tests_planned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tests_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    posture_grade: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary_metrics: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="assessments"
    )
    target_profile: Mapped["TargetProfile"] = relationship(
        "TargetProfile", back_populates="assessments"
    )
    test_results: Mapped[list["TestExecutionResult"]] = relationship(
        "TestExecutionResult", back_populates="assessment", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan"
    )
    reports: Mapped[list["ReportArtifact"]] = relationship(
        "ReportArtifact", back_populates="assessment", cascade="all, delete-orphan"
    )


class ReportArtifact(Base):
    """Generated assessment report metadata and serialized payload (DATABASE_SCHEMA.md Section 1 & SECURITY_DESIGN.md Section 5)."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    generated_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    report_format: Mapped[str] = mapped_column(
        String(20), default="HTML", nullable=False
    )
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    executive_summary: Mapped[str] = mapped_column(String(4000), default="", nullable=False)
    report_payload: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    rendered_html: Mapped[str | None] = mapped_column(
        String, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(
        "Assessment", back_populates="reports"
    )
