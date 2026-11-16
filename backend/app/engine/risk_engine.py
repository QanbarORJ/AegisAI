"""AVSS v1.0 (AI Vulnerability Scoring System) Risk Assessment Engine (`RiskAssessmentEngine`).

Implements ARCHITECTURE.md Section 5, ROADMAP.md Phase 6, and Requirement 3:
- Computes transparent, deterministic AVSS v1.0 scores (0.0 - 10.0), severity levels, and vector strings:
    Raw Score = min(10.0, (0.40*I + 0.30*E + 0.20*B + 0.10*X) * C)
- Maintains a strict architectural distinction between:
  1. Underlying Technical Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`) & `avss_score`
  2. Evidentiary Detection Confidence (`HIGH`, `MEDIUM`, `LOW`)
  3. Confirmation Status (`is_confirmed`: `True` for `FAIL`/`VULNERABLE`, `False` for `NEEDS_REVIEW`/`POTENTIALLY_VULNERABLE`)
- Low confidence (`ConfidenceLevel.LOW`) or unconfirmed status (`NEEDS_REVIEW`) NEVER automatically reduces
  the underlying technical impact, exploitability, blast radius, AVSS score, or severity level.
"""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.engine.contracts import (
    ConfidenceLevel,
    ExecutionStatus,
    NormalizedTestResult,
    SeverityLevel,
)

_AVSS_VECTOR_RE = re.compile(
    r"^AVSS:1\.0/I:(?P<I>\d+(?:\.\d+)?)/E:(?P<E>\d+(?:\.\d+)?)/"
    r"B:(?P<B>\d+(?:\.\d+)?)/X:(?P<X>\d+(?:\.\d+)?)/"
    r"C:(?P<C>\d+(?:\.\d+)?)/CONF:(?P<CONF>[A-Z]+)$"
)


class FindingRiskEvaluation(BaseModel):
    """Structured output of `RiskAssessmentEngine.evaluate_finding_risk`."""

    model_config = ConfigDict(extra="forbid")

    avss_score: float = Field(ge=0.0, le=10.0)
    severity: SeverityLevel
    confidence: ConfidenceLevel
    is_confirmed: bool
    confirmation_status: str  # "CONFIRMED" | "UNCONFIRMED_NEEDS_REVIEW"
    avss_vector: str
    impact: float
    exploitability: float
    blast_radius: float
    exposure: float
    compensating_multiplier: float
    severity_rationale: str


def map_score_to_severity(score: float) -> SeverityLevel:
    """Map numeric AVSS v1.0 score (0.0 - 10.0) to canonical SeverityLevel."""
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score >= 1.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFORMATIONAL


def compute_avss_v1(
    *,
    impact: float,
    exploitability: float,
    blast_radius: float,
    exposure: float,
    compensating_multiplier: float = 1.0,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> tuple[float, SeverityLevel, str]:
    """Compute AVSS v1.0 risk score, severity level, and vector string per ARCHITECTURE.md Section 5.

    Note: `confidence` is recorded in the vector (`CONF:<level>`) as an independent evidentiary dimension
    and never reduces the underlying technical score or `SeverityLevel`.
    """
    i_val = max(0.0, min(10.0, float(impact)))
    e_val = max(0.0, min(10.0, float(exploitability)))
    b_val = max(0.0, min(10.0, float(blast_radius)))
    x_val = max(0.0, min(10.0, float(exposure)))
    c_val = max(0.5, min(1.0, float(compensating_multiplier)))

    raw_score = min(
        10.0,
        (0.40 * i_val + 0.30 * e_val + 0.20 * b_val + 0.10 * x_val) * c_val,
    )
    score = round(raw_score, 1)
    severity = map_score_to_severity(score)

    vector = (
        f"AVSS:1.0/I:{i_val:.1f}/E:{e_val:.1f}/B:{b_val:.1f}/"
        f"X:{x_val:.1f}/C:{c_val:.2f}/CONF:{confidence.value}"
    )
    return score, severity, vector


def compute_posture_grade(
    overall_risk_score: float,
    severity_counts: dict[str, int],
) -> str:
    """Derive A-F enterprise security posture grade from aggregate risk score and finding severities."""
    if severity_counts.get("CRITICAL", 0) > 0 or overall_risk_score >= 8.5:
        return "F"
    if severity_counts.get("HIGH", 0) > 0 or overall_risk_score >= 7.0:
        return "D"
    if severity_counts.get("MEDIUM", 0) > 0 or overall_risk_score >= 4.0:
        return "C"
    if severity_counts.get("LOW", 0) > 0 or overall_risk_score >= 1.0:
        return "B"
    return "A"


def parse_avss_vector(vector: str) -> dict[str, Any] | None:
    """Parse an AVSS v1.0 vector string into its numeric components and confidence level."""
    if not vector:
        return None
    match = _AVSS_VECTOR_RE.match(vector.strip())
    if not match:
        return None
    return {
        "impact": float(match.group("I")),
        "exploitability": float(match.group("E")),
        "blast_radius": float(match.group("B")),
        "exposure": float(match.group("X")),
        "compensating_multiplier": float(match.group("C")),
        "confidence": match.group("CONF"),
    }


class RiskAssessmentEngine:
    """Computes finding-level and assessment-level AVSS v1.0 risk metrics."""

    DEFAULT_SEVERITY_DIMENSIONS: dict[SeverityLevel, tuple[float, float, float, float]] = {
        SeverityLevel.CRITICAL: (9.5, 8.5, 9.0, 8.0),
        SeverityLevel.HIGH: (8.5, 8.0, 8.0, 7.5),
        SeverityLevel.MEDIUM: (6.0, 7.0, 6.0, 7.0),
        SeverityLevel.LOW: (3.0, 5.0, 3.0, 5.0),
        SeverityLevel.INFORMATIONAL: (1.0, 2.0, 1.0, 2.0),
    }

    def evaluate_finding_risk(
        self,
        norm_result: NormalizedTestResult,
        *,
        compensating_multiplier: float = 1.0,
        compensating_controls: list[str] | None = None,
    ) -> FindingRiskEvaluation:
        """Compute AVSS v1.0 score, vector, and rationale while strictly separating severity, confidence, and confirmation."""
        comp_mult = max(0.5, min(1.0, float(compensating_multiplier)))
        is_confirmed = norm_result.execution_status == ExecutionStatus.FAIL
        confirmation_status = (
            "CONFIRMED" if is_confirmed else "UNCONFIRMED_NEEDS_REVIEW"
        )
        confidence = norm_result.confidence

        parsed = parse_avss_vector(norm_result.avss_vector)

        if parsed is not None and (
            parsed["impact"] > 0.0
            or parsed["exploitability"] > 0.0
            or parsed["blast_radius"] > 0.0
        ):
            impact = parsed["impact"]
            exploitability = parsed["exploitability"]
            blast_radius = parsed["blast_radius"]
            exposure = parsed["exposure"]
            score, severity, avss_vector = compute_avss_v1(
                impact=impact,
                exploitability=exploitability,
                blast_radius=blast_radius,
                exposure=exposure,
                compensating_multiplier=comp_mult,
                confidence=confidence,
            )
        elif norm_result.risk_score > 0.0:
            # Custom plugin supplied a direct risk_score without a populated AVSS vector
            score = round(min(10.0, norm_result.risk_score * comp_mult), 1)
            severity = (
                norm_result.severity
                if norm_result.severity != SeverityLevel.INFORMATIONAL
                else map_score_to_severity(score)
            )
            impact = norm_result.risk_score
            exploitability = norm_result.risk_score
            blast_radius = norm_result.risk_score
            exposure = norm_result.risk_score
            avss_vector = (
                f"AVSS:1.0/I:{impact:.1f}/E:{exploitability:.1f}/B:{blast_radius:.1f}/"
                f"X:{exposure:.1f}/C:{comp_mult:.2f}/CONF:{confidence.value}"
            )
        else:
            # Derive from plugin's underlying technical severity (never penalizing LOW confidence / NEEDS_REVIEW)
            impact, exploitability, blast_radius, exposure = (
                self.DEFAULT_SEVERITY_DIMENSIONS.get(
                    norm_result.severity, (6.0, 7.0, 6.0, 7.0)
                )
            )
            score, severity, avss_vector = compute_avss_v1(
                impact=impact,
                exploitability=exploitability,
                blast_radius=blast_radius,
                exposure=exposure,
                compensating_multiplier=comp_mult,
                confidence=confidence,
            )

        comp_note = ""
        if compensating_controls:
            comp_note = (
                f" Verified compensating controls ({', '.join(compensating_controls)}) "
                f"applied multiplier C={comp_mult:.2f}."
            )

        confirmation_note = (
            f"Confirmation Status: {confirmation_status} "
            f"(Detection Confidence: {confidence.value}; underlying severity={severity.value} "
            f"and AVSS={score}/10.0 are evaluated independently of confidence)."
        )

        base_rationale = (norm_result.risk_rationale or "").strip()
        if base_rationale:
            rationale = f"{base_rationale} [{avss_vector}] {confirmation_note}{comp_note}".strip()
        else:
            rationale = (
                f"Assigned {severity.value} severity (AVSS {score}/10.0, vector {avss_vector}) "
                f"for component '{norm_result.target_component}'. {confirmation_note}{comp_note}"
            ).strip()

        return FindingRiskEvaluation(
            avss_score=score,
            severity=severity,
            confidence=confidence,
            is_confirmed=is_confirmed,
            confirmation_status=confirmation_status,
            avss_vector=avss_vector,
            impact=impact,
            exploitability=exploitability,
            blast_radius=blast_radius,
            exposure=exposure,
            compensating_multiplier=comp_mult,
            severity_rationale=rationale,
        )
