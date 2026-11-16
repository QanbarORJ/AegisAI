"""Shared Multi-Probe Outcome Consolidation Helper for AegisAI Scanner Modules (LLM, RAG, Agent).

Strictly enforces the canonical outcome precedence:
1. FAIL (VULNERABLE) — Deterministic runtime exploitation or verified architectural/config weakness.
2. ERROR (UNDETERMINED) — Upstream HTTP 5xx, timeout, rate-limit, or transport error (never reported as PASS).
3. NEEDS_REVIEW (POTENTIALLY_VULNERABLE) — Ambiguous behavioral indicator requiring human analyst verification.
4. PASS (SECURE) — All probes completed cleanly without vulnerability or ambiguity.
"""

from typing import Any

from app.engine.contracts import (
    BaseSecurityTest,
    ConfidenceLevel,
    ExecutionStatus,
    NormalizedTestResult,
    SeverityLevel,
    TechnicalEvidenceItem,
    TestContext,
    VulnerabilityStatus,
)
from app.engine.risk_engine import compute_avss_v1


def finalize_multi_probe_outcome(
    *,
    plugin: BaseSecurityTest,
    context: TestContext,
    probes_sent: int,
    fail_evidence: list[TechnicalEvidenceItem],
    review_evidence: list[TechnicalEvidenceItem],
    transport_errors: list[str],
    impact: float,
    exploitability: float,
    blast_radius: float,
    exposure: float,
    fail_rationale: str,
    review_rationale: str,
    pass_rationale: str,
    framework_references: list[dict[str, Any]],
    remediation: dict[str, Any],
    extra_execution_log: dict[str, Any] | None = None,
) -> NormalizedTestResult:
    """Consolidate multi-probe outcomes while strictly separating FAIL, ERROR, NEEDS_REVIEW, and PASS."""
    comp_mult = (
        context.architecture_analysis.compensating_multiplier
        if context.architecture_analysis
        else 1.0
    )
    extra_log = extra_execution_log or {}

    # 1. Deterministic FAIL takes highest precedence
    if fail_evidence:
        score, severity, vector = compute_avss_v1(
            impact=impact,
            exploitability=exploitability,
            blast_radius=blast_radius,
            exposure=exposure,
            compensating_multiplier=comp_mult,
            confidence=ConfidenceLevel.HIGH,
        )
        return NormalizedTestResult(
            test_id=plugin.test_id,
            test_title=plugin.title,
            assessment_id=context.assessment_id,
            target_component=plugin.target_component,
            test_category=plugin.category,
            module=plugin.module,
            execution_status=ExecutionStatus.FAIL,
            vulnerability_status=VulnerabilityStatus.VULNERABLE,
            severity=severity,
            confidence=ConfidenceLevel.HIGH,
            risk_score=score,
            avss_vector=vector,
            risk_rationale=fail_rationale,
            description=plugin.description,
            exploitability_summary=plugin.exploitability_summary,
            probes_sent=probes_sent,
            execution_log={
                "probes_sent": probes_sent,
                "failed_probes": len(fail_evidence),
                "transport_errors": transport_errors,
                **extra_log,
            },
            technical_evidence=fail_evidence,
            framework_references=framework_references,
            recommended_remediation=remediation,
        )

    # 2. If any transport error occurred and no deterministic FAIL was confirmed, report ERROR (never PASS!)
    if transport_errors:
        return NormalizedTestResult(
            test_id=plugin.test_id,
            test_title=plugin.title,
            assessment_id=context.assessment_id,
            target_component=plugin.target_component,
            test_category=plugin.category,
            module=plugin.module,
            execution_status=ExecutionStatus.ERROR,
            vulnerability_status=VulnerabilityStatus.UNDETERMINED,
            severity=SeverityLevel.INFORMATIONAL,
            confidence=ConfidenceLevel.LOW,
            risk_score=0.0,
            risk_rationale=(
                f"Test encountered {len(transport_errors)} transport/upstream error(s) and could not "
                f"deterministically verify security posture: {'; '.join(transport_errors)}"
            ),
            description=plugin.description,
            exploitability_summary=plugin.exploitability_summary,
            probes_sent=probes_sent,
            execution_log={
                "error_code": "PROBE_TRANSPORT_ERROR",
                "transport_errors": transport_errors,
                **extra_log,
            },
            technical_evidence=[],
            framework_references=framework_references,
            recommended_remediation=remediation,
        )

    # 3. Ambiguous behavioral indicators require human review (NEEDS_REVIEW)
    #    Strict separation (Requirement 3): Low confidence / unconfirmed status does NOT reduce
    #    the underlying technical severity or AVSS score.
    if review_evidence:
        score, severity, vector = compute_avss_v1(
            impact=impact,
            exploitability=exploitability,
            blast_radius=blast_radius,
            exposure=exposure,
            compensating_multiplier=comp_mult,
            confidence=ConfidenceLevel.LOW,
        )
        return NormalizedTestResult(
            test_id=plugin.test_id,
            test_title=plugin.title,
            assessment_id=context.assessment_id,
            target_component=plugin.target_component,
            test_category=plugin.category,
            module=plugin.module,
            execution_status=ExecutionStatus.NEEDS_REVIEW,
            vulnerability_status=VulnerabilityStatus.POTENTIALLY_VULNERABLE,
            severity=severity,
            confidence=ConfidenceLevel.LOW,
            risk_score=score,
            avss_vector=vector,
            risk_rationale=review_rationale,
            description=plugin.description,
            exploitability_summary=plugin.exploitability_summary,
            probes_sent=probes_sent,
            execution_log={
                "probes_sent": probes_sent,
                "review_probes": len(review_evidence),
                **extra_log,
            },
            technical_evidence=review_evidence,
            framework_references=framework_references,
            recommended_remediation=remediation,
        )

    # 4. All probes completed cleanly without vulnerability or ambiguity -> PASS
    return NormalizedTestResult(
        test_id=plugin.test_id,
        test_title=plugin.title,
        assessment_id=context.assessment_id,
        target_component=plugin.target_component,
        test_category=plugin.category,
        module=plugin.module,
        execution_status=ExecutionStatus.PASS,
        vulnerability_status=VulnerabilityStatus.SECURE,
        severity=SeverityLevel.INFORMATIONAL,
        confidence=ConfidenceLevel.HIGH,
        risk_score=0.0,
        risk_rationale=pass_rationale,
        description=plugin.description,
        exploitability_summary=plugin.exploitability_summary,
        probes_sent=probes_sent,
        execution_log={"probes_sent": probes_sent, "outcome": "ALL_PROBES_MITIGATED", **extra_log},
        technical_evidence=[],
        framework_references=framework_references,
        recommended_remediation=remediation,
    )
