"""Automatic Evidence Collector & Header/Secret/PII Redaction Pipeline.

Implements SECURITY_DESIGN.md Section 4.2 and mitigates TM-02 & TM-05:
1. Header Redaction: Authorization, X-API-Key, Cookie, Set-Cookie -> [REDACTED_CREDENTIAL]
2. Secret Pattern Redaction: OpenAI/Anthropic keys (sk-...), AWS keys (AKIA...), JWTs (eyJ...), Bearer tokens
3. PII Pattern Redaction: SSNs, payment card numbers (with Luhn validation), and sensitive secret fields
4. Masked Proof Snippet Extraction for Sensitive Information Disclosure (LLM-SID-001)
"""

import re
from typing import Any

from app.engine.contracts import StandardizedTargetResponse, TechnicalEvidenceItem

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "api-key",
    "cookie",
    "set-cookie",
    "x-tenant-a-token",
    "x-tenant-b-token",
}

_SENSITIVE_DICT_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "x-api-key",
    "bearer_token",
    "access_token",
    "refresh_token",
    "client_secret",
    "password",
    "secret",
    "private_key",
    "tenant_a_token",
    "tenant_b_token",
    "cookie",
    "set-cookie",
}

_OPENAI_KEY_RE = re.compile(
    r"\bsk-(?:proj-|ant-(?:api\d+-)?|live-|test-)?[a-zA-Z0-9_\-]{12,}\b"
)
_AWS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_JWT_RE = re.compile(
    r"\beyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b"
)
_BEARER_RE = re.compile(
    r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.~+/]{8,}=*"
)
_INLINE_KV_SECRET_RE = re.compile(
    r"(?i)\b(api_key|apikey|x-api-key|password|client_secret|secret_key)\s*([:=])\s*(['\"]?)([^\s,'\"\}]{6,})\3"
)
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _passes_luhn(digits: str) -> bool:
    """Verify if a numeric string of 13-19 digits passes the Luhn checksum algorithm."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


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
    if not text:
        return text

    sanitized = _BEARER_RE.sub(r"\1[REDACTED_CREDENTIAL]", text)
    sanitized = _OPENAI_KEY_RE.sub("sk-[REDACTED_API_KEY]", sanitized)
    sanitized = _AWS_KEY_RE.sub("AKIA[REDACTED_AWS_KEY]", sanitized)
    sanitized = _JWT_RE.sub("eyJ[REDACTED_JWT_TOKEN]", sanitized)
    sanitized = _INLINE_KV_SECRET_RE.sub(
        r"\1\2\3[REDACTED_SECRET]\3", sanitized
    )
    sanitized = _SSN_RE.sub("[REDACTED_SSN]", sanitized)

    def _replace_cc(match: re.Match[str]) -> str:
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if _passes_luhn(digits):
            return f"[REDACTED_PAYMENT_CARD_ENDING_{digits[-4:]}]"
        return candidate

    sanitized = _CC_CANDIDATE_RE.sub(_replace_cc, sanitized)
    return sanitized


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Redact authentication and session headers with '[REDACTED_CREDENTIAL]'."""
    if not headers:
        return {}
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k)
        if key_str.strip().lower() in _SENSITIVE_HEADER_NAMES:
            redacted[key_str] = "[REDACTED_CREDENTIAL]"
        else:
            redacted[key_str] = redact_string(str(v))
    return redacted


def sanitize_payload(payload: Any) -> Any:
    """Recursively sanitize dictionaries, lists, and strings for safe persistence in TechnicalEvidence."""
    if payload is None:
        return {}
    if isinstance(payload, str):
        return redact_string(payload)
    if isinstance(payload, (int, float, bool)):
        return payload
    if isinstance(payload, (list, tuple, set)):
        return [sanitize_payload(item) for item in payload]
    if isinstance(payload, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in payload.items():
            key_str = str(k)
            key_lower = key_str.strip().lower()
            if key_lower == "headers" and isinstance(v, dict):
                sanitized_dict[key_str] = redact_headers(v)
            elif key_lower in _SENSITIVE_DICT_KEYS:
                sanitized_dict[key_str] = "[REDACTED_CREDENTIAL]"
            else:
                sanitized_dict[key_str] = sanitize_payload(v)
        return sanitized_dict
    return redact_string(str(payload))


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
