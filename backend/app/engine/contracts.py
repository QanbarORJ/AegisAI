"""Standardized contracts, enums, and base plugin interfaces for the AegisAI Assessment Engine.

Implements ARCHITECTURE.md Section 4.2 & 4.3 and ROADMAP.md Phase 3 deliverables.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionStatus(StrEnum):
    """Canonical test execution outcome (strictly separating ERROR from PASS/FAIL)."""

    PASS = "PASS"  # Test executed; target demonstrated expected secure behavior
    FAIL = "FAIL"  # Test executed; deterministic evidence of vulnerability confirmed
    ERROR = "ERROR"  # Network timeout, HTTP 5xx, rate limit, or target unreachable (NOT a pass!)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Target architecture does not include this component
    NEEDS_REVIEW = "NEEDS_REVIEW"  # Ambiguous behavioral indicator; requires human analyst review


class VulnerabilityStatus(StrEnum):
    """Canonical vulnerability determination status paired with ExecutionStatus."""

    VULNERABLE = "VULNERABLE"
    SECURE = "SECURE"
    UNDETERMINED = "UNDETERMINED"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"


class SeverityLevel(StrEnum):
    """AVSS v1.0 aligned severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ConfidenceLevel(StrEnum):
    """Detection confidence level."""

    HIGH = "HIGH"  # Deterministic canary/structural proof (e.g., nonce leaked, XSS tag unescaped)
    MEDIUM = "MEDIUM"  # Strong behavioral pattern across multiple probes
    LOW = "LOW"  # Heuristic indicator only; flagged as NEEDS_REVIEW


class ScannerModule(StrEnum):
    """Top-level assessment scanner modules."""

    LLM = "LLM"
    RAG = "RAG"
    AGENT = "AGENT"
    CONFIG = "CONFIG"


class TechnicalEvidenceItem(BaseModel):
    """Single sanitized probe request/response trace and detector match proof."""

    model_config = ConfigDict(extra="ignore")

    probe_index: int = Field(ge=0)
    probe_name: str
    request_payload_redacted: dict[str, Any] | str
    response_body_redacted: dict[str, Any] | str
    http_status_code: int | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    detector_type: str  # e.g., "CANARY_TOKEN_MATCH", "SINK_AST_DETECTOR", "CONFIG_RULE"
    matched_indicators: list[str] = Field(default_factory=list)
    target_component: str  # e.g., "LLM_SYSTEM_PROMPT_BOUNDARY", "RAG_METADATA_FILTER"


class NormalizedTestResult(BaseModel):
    """Standardized output contract returned by every BaseSecurityTest plugin."""

    model_config = ConfigDict(extra="ignore")

    test_id: str  # e.g., "LLM-PI-001"
    test_title: str = ""
    assessment_id: str
    target_component: str
    test_category: str  # e.g., "Direct Prompt Injection"
    module: str  # "LLM" | "RAG" | "AGENT" | "CONFIG"
    execution_status: ExecutionStatus
    vulnerability_status: VulnerabilityStatus
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    avss_vector: str = "AVSS:1.0/I:0.0/E:0.0/B:0.0/X:0.0/C:1.0/CONF:HIGH"
    risk_rationale: str = ""
    description: str = ""
    exploitability_summary: str = ""
    probes_sent: int = Field(default=0, ge=0)
    execution_duration_ms: float = Field(default=0.0, ge=0.0)
    execution_log: dict[str, Any] = Field(default_factory=dict)
    technical_evidence: list[TechnicalEvidenceItem] = Field(default_factory=list)
    framework_references: list[dict[str, Any]] = Field(default_factory=list)
    recommended_remediation: dict[str, Any] = Field(default_factory=dict)
    execution_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_status_invariants(self) -> "NormalizedTestResult":
        """Enforce strict separation between PASS, FAIL, ERROR, NOT_APPLICABLE, and NEEDS_REVIEW."""
        if self.execution_status in (ExecutionStatus.ERROR, ExecutionStatus.NOT_APPLICABLE):
            if self.vulnerability_status != VulnerabilityStatus.UNDETERMINED:
                raise ValueError(
                    f"execution_status={self.execution_status.value} requires "
                    f"vulnerability_status=UNDETERMINED (got {self.vulnerability_status.value})."
                )
        elif self.execution_status == ExecutionStatus.PASS:
            if self.vulnerability_status != VulnerabilityStatus.SECURE:
                raise ValueError(
                    f"execution_status=PASS requires vulnerability_status=SECURE "
                    f"(got {self.vulnerability_status.value})."
                )
        elif self.execution_status == ExecutionStatus.FAIL:
            if self.vulnerability_status != VulnerabilityStatus.VULNERABLE:
                raise ValueError(
                    f"execution_status=FAIL requires vulnerability_status=VULNERABLE "
                    f"(got {self.vulnerability_status.value})."
                )
        elif self.execution_status == ExecutionStatus.NEEDS_REVIEW:
            if self.vulnerability_status not in (
                VulnerabilityStatus.POTENTIALLY_VULNERABLE,
                VulnerabilityStatus.UNDETERMINED,
            ):
                raise ValueError(
                    f"execution_status=NEEDS_REVIEW requires vulnerability_status in "
                    f"(POTENTIALLY_VULNERABLE, UNDETERMINED) (got {self.vulnerability_status.value})."
                )
        return self


class StandardizedTargetResponse(BaseModel):
    """Uniform response envelope returned by all TargetAdapters."""

    model_config = ConfigDict(extra="ignore")

    status_code: int | None = None
    output_text: str = ""
    raw_request: dict[str, Any] = Field(default_factory=dict)
    raw_response: dict[str, Any] | str = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)
    retrieved_chunks: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    guardrail_blocked: bool = False
    error_type: str | None = None  # e.g., "TIMEOUT", "HTTP_5XX", "RATE_LIMITED", "NETWORK_ERROR"
    error_message: str | None = None

    @property
    def is_transport_error(self) -> bool:
        """Return True if the probe failed due to network/timeout/5xx/rate-limit error."""
        if self.error_type is not None:
            return True
        if self.status_code is not None and (self.status_code >= 500 or self.status_code == 429):
            return True
        return False


class TargetProfileResult(BaseModel):
    """Connectivity, authentication, and baseline telemetry gathered by TargetProfiler."""

    reachable: bool
    status_code: int | None = None
    baseline_latency_ms: float = 0.0
    auth_verified: bool = False
    detected_capabilities: list[str] = Field(default_factory=list)
    guardrail_detected: bool = False
    guardrail_signature: str | None = None
    ssrf_validated_ips: list[str] = Field(default_factory=list)
    error_reason: str | None = None


class ArchitectureAnalysisResult(BaseModel):
    """Static analysis summary of the target's declared architecture manifest and harness configs."""

    architecture_type: str
    identified_components: list[str] = Field(default_factory=list)
    config_weaknesses: list[dict[str, Any]] = Field(default_factory=list)
    compensating_controls: list[str] = Field(default_factory=list)
    compensating_multiplier: float = Field(default=1.0, ge=0.5, le=1.0)
    summary: dict[str, Any] = Field(default_factory=dict)


class TestContext(BaseModel):
    """Immutable execution context passed to every security test plugin during an assessment."""

    __test__ = False
    model_config = ConfigDict(extra="ignore")

    assessment_id: str
    organization_id: str
    target_id: str
    target_name: str
    architecture_type: str
    integration_mode: str
    endpoint_url: str
    allowed_hosts: list[str]
    request_template: dict[str, Any] = Field(default_factory=dict)
    architecture_manifest: dict[str, Any] = Field(default_factory=dict)
    rag_harness_config: dict[str, Any] | None = None
    agent_harness_config: dict[str, Any] | None = None
    scope_attestation: dict[str, Any] = Field(default_factory=dict)
    profile_result: TargetProfileResult | None = None
    architecture_analysis: ArchitectureAnalysisResult | None = None
    max_probes_per_test: int = Field(default=10, ge=1, le=50)
    mutating_confirmed: bool = False


class BaseSecurityTest(ABC):
    """Abstract base class for all AegisAI modular security test plugins."""

    test_id: str = ""
    title: str = ""
    category: str = ""
    module: str = ScannerModule.LLM.value
    target_component: str = "LLM_APPLICATION_ENDPOINT"
    applicable_architectures: list[str] = ["LLM_APP", "RAG_PIPELINE", "AI_AGENT", "HYBRID"]
    mutating_risk: bool = False
    default_severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    exploitability_summary: str = ""

    def is_applicable(self, context: TestContext) -> tuple[bool, str]:
        """Check whether this test applies to the target's architecture and safety constraints."""
        if (
            self.applicable_architectures
            and context.architecture_type not in self.applicable_architectures
            and context.architecture_type != "HYBRID"
        ):
            return (
                False,
                f"Test '{self.test_id}' requires architecture in {self.applicable_architectures}, "
                f"but target is '{context.architecture_type}'.",
            )

        if self.mutating_risk and not context.mutating_confirmed:
            # Check scope_attestation for non_destructive / sandbox confirmation
            sandbox_attested = bool(
                context.scope_attestation.get("agent_sandbox_confirmed")
                or context.scope_attestation.get("dry_run_confirmed")
                or (context.agent_harness_config or {}).get("dry_run", False)
                or context.integration_mode in ("SIMULATOR", "CONFIG_ONLY")
            )
            if not sandbox_attested:
                return (
                    False,
                    f"Test '{self.test_id}' carries mutating risk and requires sandbox/dry-run attestation.",
                )

        return True, "Applicable"

    @abstractmethod
    async def execute(self, context: TestContext, adapter: Any) -> NormalizedTestResult:
        """Execute security probes against the target via `adapter` and return a NormalizedTestResult."""
        raise NotImplementedError
