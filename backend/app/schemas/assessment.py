"""Assessment, TestExecutionResult, Finding, and TechnicalEvidence Pydantic v2 schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engine.report_generator import extract_finding_framework_mappings
from app.models.assessment import AssessmentStatusEnum
from app.models.finding import Finding


class ScopeAttestationPayload(BaseModel):
    """Explicit legal and technical scope authorization payload (SECURITY_DESIGN.md Section 2)."""

    authorized: bool = Field(
        description="Must be True to confirm explicit legal/organizational authorization to test the target."
    )
    authorizer_name: str = Field(default="Authorized Security Engineer", min_length=2, max_length=160)
    authorizer_title: str = Field(default="Security Engineer", max_length=120)
    agent_sandbox_confirmed: bool = Field(
        default=False,
        description="Confirms any Agent tool execution endpoints are running in sandbox or dry-run mode.",
    )
    notes: str | None = Field(default=None, max_length=1000)


class AssessmentCreateRequest(BaseModel):
    """Request payload to create (and optionally attest) a new security assessment."""

    name: str = Field(min_length=2, max_length=200)
    target_profile_id: str = Field(min_length=1, max_length=64)
    selected_modules: list[str] = Field(
        default_factory=lambda: ["LLM"],
        min_length=1,
    )
    scope_attestation: ScopeAttestationPayload


class TechnicalEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    probe_name: str
    request_payload: dict[str, Any]
    response_payload: dict[str, Any]
    http_status: int | None = None
    latency_ms: float | None = None
    detector_name: str
    matched_artifacts: list[str]
    captured_at: datetime


class FindingFrameworkMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    framework_control_id: str | None = None
    framework_id: str
    framework_name: str
    framework_version: str
    publisher: str
    control_id: str
    title: str
    category: str
    official_reference_url: str
    mapping_type: str
    mapping_rationale: str


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    assessment_id: str
    test_result_id: str
    test_id: str
    title: str
    module: str
    category: str
    affected_component: str
    severity: str
    confidence: str
    is_confirmed: bool
    avss_score: float
    avss_vector: str
    severity_rationale: str
    description: str
    exploitability_summary: str
    remediation_structured: dict[str, Any]
    evidence_items: list[TechnicalEvidenceResponse] = Field(default_factory=list)
    framework_mappings: list[FindingFrameworkMappingResponse] = Field(default_factory=list)
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _populate_resolved_framework_mappings(cls, data: Any) -> Any:
        if isinstance(data, Finding):
            return {
                "id": data.id,
                "organization_id": data.organization_id,
                "assessment_id": data.assessment_id,
                "test_result_id": data.test_result_id,
                "test_id": data.test_id,
                "title": data.title,
                "module": data.module,
                "category": data.category,
                "affected_component": data.affected_component,
                "severity": data.severity,
                "confidence": data.confidence,
                "is_confirmed": data.is_confirmed,
                "avss_score": data.avss_score,
                "avss_vector": data.avss_vector,
                "severity_rationale": data.severity_rationale,
                "description": data.description,
                "exploitability_summary": data.exploitability_summary,
                "remediation_structured": data.remediation_structured,
                "evidence_items": data.evidence_items,
                "framework_mappings": extract_finding_framework_mappings(data),
                "created_at": data.created_at,
            }
        return data


class TestExecutionResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    test_id: str
    module: str
    test_title: str
    test_category: str
    target_component: str
    execution_status: str
    vulnerability_status: str
    probes_sent: int
    execution_duration_ms: float
    execution_log: dict[str, Any]
    executed_at: datetime


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    target_profile_id: str
    initiated_by_user_id: str
    name: str
    selected_modules: list[str]
    status: AssessmentStatusEnum
    scope_attestation: dict[str, Any]
    target_profile_snapshot: dict[str, Any]
    progress_pct: int
    total_tests_planned: int
    tests_completed: int
    overall_risk_score: float
    posture_grade: str | None = None
    summary_metrics: dict[str, Any]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime


class AssessmentDetailResponse(AssessmentResponse):
    """Detailed assessment response including test execution matrix and findings."""

    test_results: list[TestExecutionResultResponse] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)
