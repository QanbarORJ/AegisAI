"""Automatic Evidence Collector & Header/Secret/PII Redaction Pipeline.

Implements SECURITY_DESIGN.md Section 4.2 and mitigates TM-02 & TM-05:
1. Header Redaction: Authorization, X-API-Key, Cookie, Set-Cookie -> [REDACTED_CREDENTIAL]
2. Secret Pattern Redaction: OpenAI/Anthropic keys (sk-...), AWS keys (AKIA...), JWTs (eyJ...), Bearer tokens
3. PII Pattern Redaction: SSNs, payment card numbers (with Luhn validation), and sensitive secret fields
4. Masked Proof Snippet Extraction for Sensitive Information Disclosure (LLM-SID-001)
"""

import re
from typing import Any

from app.core.logging import (
    _AWS_KEY_RE,
    _CC_CANDIDATE_RE,
    _GITHUB_TOKEN_RE,
    _GOOGLE_KEY_RE,
    _JWT_RE,
    _OPENAI_KEY_RE,
    _SLACK_TOKEN_RE,
    _SSN_RE,
    passes_luhn,
    redact_headers_dict,
    redact_sensitive_text,
    sanitize_structured_payload,
)
from app.engine.contracts import StandardizedTargetResponse, TechnicalEvidenceItem

_passes_luhn = passes_luhn


def mask_secret_artifact(artifact_type: str, raw_value: str) -> str:
    """Create a masked proof snippet (e.g., 'Matched AWS Access Key ID: AKIA************7X9Q')."""
    cleaned = raw_value.strip()
    if len(cleaned) <= 8:
        masked = "****"
    else:
        prefix = cleaned[:4]
        suffix = cleaned[-4:]
        masked = f"{prefix}{'*' * 12}{suffix}"
    return f"Matched {artifact_type}: {masked}"


def detect_and_mask_sensitive_artifacts(text: str) -> list[str]:
    """Scan text for secrets/PII and return masked proof descriptors without storing raw values."""
    if not text:
        return []

    findings: list[str] = []

    for match in _AWS_KEY_RE.finditer(text):
        findings.append(mask_secret_artifact("AWS Access Key ID", match.group(1)))

    for match in _OPENAI_KEY_RE.finditer(text):
        findings.append(mask_secret_artifact("API Secret Key", match.group(0)))

    for match in _GITHUB_TOKEN_RE.finditer(text):
        findings.append(mask_secret_artifact("GitHub Token", match.group(0)))

    for match in _SLACK_TOKEN_RE.finditer(text):
        findings.append(mask_secret_artifact("Slack Token", match.group(0)))

    for match in _GOOGLE_KEY_RE.finditer(text):
        findings.append(mask_secret_artifact("Google API Key", match.group(0)))

    for match in _JWT_RE.finditer(text):
        findings.append(mask_secret_artifact("JWT Bearer Token", match.group(0)))

    for match in _SSN_RE.finditer(text):
        raw_ssn = match.group(0)
        findings.append(f"Matched US SSN Pattern: ***-**-{raw_ssn[-4:]}")

    for match in _CC_CANDIDATE_RE.finditer(text):
        raw_cc = match.group(0)
        digits = re.sub(r"\D", "", raw_cc)
        if _passes_luhn(digits):
            findings.append(f"Matched Payment Card (Luhn Valid): ****-****-****-{digits[-4:]}")

    return findings


def redact_string(text: str) -> str:
    """Scrub secrets, tokens, SSNs, and Luhn-valid payment cards from a string."""
    return redact_sensitive_text(text)


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Redact authentication and session headers with '[REDACTED_CREDENTIAL]'."""
    return redact_headers_dict(headers, credential_placeholder="[REDACTED_CREDENTIAL]")


def sanitize_payload(payload: Any) -> Any:
    """Recursively sanitize dictionaries, lists, tuples, and strings for safe persistence in TechnicalEvidence."""
    return sanitize_structured_payload(
        payload, credential_placeholder="[REDACTED_CREDENTIAL]"
    )


class EvidenceCollector:
    """Constructs sanitized TechnicalEvidenceItem objects from probe exchanges."""

    @staticmethod
    def build_evidence_item(
        *,
        probe_index: int,
        probe_name: str,
        response: StandardizedTargetResponse,
        detector_type: str,
        matched_indicators: list[str],
        target_component: str,
    ) -> TechnicalEvidenceItem:
        """Sanitize request/response payloads and return a TechnicalEvidenceItem."""
        req_sanitized = sanitize_payload(response.raw_request)
        if isinstance(req_sanitized, str):
            req_sanitized = {"body": req_sanitized}

        resp_raw: Any = response.raw_response
        if isinstance(resp_raw, str):
            resp_sanitized: dict[str, Any] | str = {
                "output_text": redact_string(resp_raw),
                "headers": redact_headers(response.response_headers),
            }
        elif isinstance(resp_raw, dict):
            resp_sanitized = sanitize_payload(resp_raw)
            if response.response_headers and "headers" not in resp_sanitized:
                resp_sanitized["_headers"] = redact_headers(response.response_headers)
        else:
            resp_sanitized = {
                "output_text": redact_string(response.output_text),
                "headers": redact_headers(response.response_headers),
            }

        sanitized_indicators = [redact_string(str(ind)) for ind in matched_indicators]

        return TechnicalEvidenceItem(
            probe_index=probe_index,
            probe_name=probe_name,
            request_payload_redacted=req_sanitized,
            response_body_redacted=resp_sanitized,
            http_status_code=response.status_code,
            latency_ms=round(response.latency_ms, 2),
            detector_type=detector_type,
            matched_indicators=sanitized_indicators,
            target_component=target_component,
        )

    @staticmethod
    def sanitize_evidence_item(item: TechnicalEvidenceItem) -> TechnicalEvidenceItem:
        """Ensure an already-created TechnicalEvidenceItem is fully redacted."""
        req_redacted = sanitize_payload(item.request_payload_redacted)
        resp_redacted = sanitize_payload(item.response_body_redacted)
        indicators_redacted = [
            redact_string(str(ind)) for ind in item.matched_indicators
        ]
        return item.model_copy(
            update={
                "request_payload_redacted": req_redacted,
                "response_body_redacted": resp_redacted,
                "matched_indicators": indicators_redacted,
            }
        )
