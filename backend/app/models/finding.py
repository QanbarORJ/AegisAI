"""TestExecutionResult, Finding, and TechnicalEvidence ORM models (DATABASE_SCHEMA.md Section 2.3)."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JsonVariant, utc_now

if TYPE_CHECKING:
    from app.models.assessment import Assessment
    from app.models.framework import FindingFrameworkMapping


class TestExecutionResult(Base):
    """Normalized record of every security test executed during an assessment."""

    __tablename__ = "test_execution_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    test_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    module: Mapped[str] = mapped_column(String(30), nullable=False)
    test_title: Mapped[str] = mapped_column(String(200), nullable=False)
    test_category: Mapped[str] = mapped_column(String(100), nullable=False)
    target_component: Mapped[str] = mapped_column(String(100), nullable=False)
    execution_status: Mapped[str] = mapped_column(String(30), index=True, nullable=False)
    vulnerability_status: Mapped[str] = mapped_column(String(40), nullable=False)
    probes_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    execution_duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    execution_log: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(
        "Assessment", back_populates="test_results"
    )


class Finding(Base):
    """Confirmed (FAIL) or suspected (NEEDS_REVIEW) security vulnerability finding."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    test_result_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("test_execution_results.id", ondelete="CASCADE"), nullable=False
    )
    test_id: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    module: Mapped[str] = mapped_column(String(30), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    affected_component: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    avss_score: Mapped[float] = mapped_column(Float, nullable=False)
    avss_vector: Mapped[str] = mapped_column(String(140), nullable=False)
    severity_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    exploitability_summary: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_structured: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    assessment: Mapped["Assessment"] = relationship(
        "Assessment", back_populates="findings"
    )
    evidence_items: Mapped[list["TechnicalEvidence"]] = relationship(
        "TechnicalEvidence", back_populates="finding", cascade="all, delete-orphan"
    )
    framework_mappings: Mapped[list["FindingFrameworkMapping"]] = relationship(
        "FindingFrameworkMapping", back_populates="finding", cascade="all, delete-orphan"
    )


class TechnicalEvidence(Base):
    """Sanitized and redacted technical proof supporting a Finding."""

    __tablename__ = "technical_evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    probe_name: Mapped[str] = mapped_column(String(160), nullable=False)
    request_payload: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    response_payload: Mapped[dict[str, Any]] = mapped_column(
        JsonVariant, default=dict, nullable=False
    )
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    detector_name: Mapped[str] = mapped_column(String(80), nullable=False)
    matched_artifacts: Mapped[list[str]] = mapped_column(
        JsonVariant, default=list, nullable=False
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    finding: Mapped["Finding"] = relationship(
        "Finding", back_populates="evidence_items"
    )
