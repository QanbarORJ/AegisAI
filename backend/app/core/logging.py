"""Structured logging and unified credential/secret/PII redaction primitives (Mitigates TM-02 & TM-05)."""

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

SENSITIVE_HEADER_NAMES: set[str] = {
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

SENSITIVE_DICT_KEYS: set[str] = {
    "authorization",
    "proxy-authorization",
    "api_key",
    "apikey",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "bearer_token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "session_token",
    "api_token",
    "secret_token",
    "token",
    "jwt",
    "jwt_token",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "private_key",
    "aws_secret_access_key",
    "tenant_a_token",
    "tenant_b_token",
    "primary_token",
    "secondary_token",
    "cookie",
    "set-cookie",
    "credentials",
    "encrypted_credentials",
}

_SAFE_NON_SECRET_DICT_KEYS: set[str] = {
    "credential_preview",
    "scope_attestation_hash",
    "max_tokens",
    "completion_tokens",
    "prompt_tokens",
    "total_tokens",
    "token_type",
    "canary_token",
    "canary_tokens",
}

_SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "token",
    "credential",
)

_OPENAI_KEY_RE = re.compile(
    r"\bsk-(?:proj-|ant-(?:api\d+-)?|live-|test-)?[a-zA-Z0-9_\-]{12,}\b"
)
_AWS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
_GITHUB_TOKEN_RE = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})\b"
)
_SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[a-zA-Z0-9\-]{10,})\b")
_GOOGLE_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")
_JWT_RE = re.compile(
    r"\beyJ[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\.[a-zA-Z0-9_\-]{8,}\b"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.~+/]{8,}=*")
_INLINE_KV_SECRET_RE = re.compile(
    r"(?i)\b(api_key|apikey|x-api-key|x-auth-token|auth_token|access_token|refresh_token|"
    r"bearer_token|secret_token|api_token|password|passwd|client_secret|secret_key|"
    r"aws_secret_access_key|secret)\s*([:=])\s*(['\"]?)([^\s,'\"\}]{6,})\3"
)
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def passes_luhn(digits: str) -> bool:
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


def is_sensitive_dict_key(key: str) -> bool:
    """Return True if a dictionary key name represents a secret, token, password, or credential."""
    key_lower = key.strip().lower()
    if not key_lower or key_lower in _SAFE_NON_SECRET_DICT_KEYS:
        return False
    if key_lower in SENSITIVE_DICT_KEYS:
        return True
    if key_lower.endswith("_token") and key_lower != "canary_token":
        return True
    return any(sub in key_lower for sub in _SENSITIVE_KEY_SUBSTRINGS)


def redact_sensitive_text(text: str) -> str:
    """Scrub API keys, Bearer tokens, AWS keys, JWTs, inline secrets, SSNs, and Luhn payment cards."""
    if not text:
        return text

    sanitized = _BEARER_RE.sub(r"\1[REDACTED_CREDENTIAL]", text)
    sanitized = _OPENAI_KEY_RE.sub("sk-[REDACTED_API_KEY]", sanitized)
    sanitized = _AWS_KEY_RE.sub("AKIA[REDACTED_AWS_KEY]", sanitized)
    sanitized = _GITHUB_TOKEN_RE.sub("ghp_[REDACTED_API_KEY]", sanitized)
    sanitized = _SLACK_TOKEN_RE.sub("xox-[REDACTED_API_KEY]", sanitized)
    sanitized = _GOOGLE_KEY_RE.sub("AIza[REDACTED_API_KEY]", sanitized)
    sanitized = _JWT_RE.sub("eyJ[REDACTED_JWT_TOKEN]", sanitized)
    sanitized = _INLINE_KV_SECRET_RE.sub(r"\1\2\3[REDACTED_SECRET]\3", sanitized)
    sanitized = _SSN_RE.sub("[REDACTED_SSN]", sanitized)

    def _replace_cc(match: re.Match[str]) -> str:
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if passes_luhn(digits):
            return f"[REDACTED_PAYMENT_CARD_ENDING_{digits[-4:]}]"
        return candidate

    sanitized = _CC_CANDIDATE_RE.sub(_replace_cc, sanitized)
    return sanitized


def redact_headers_dict(
    headers: dict[str, Any] | None,
    *,
    credential_placeholder: str = "[REDACTED_CREDENTIAL]",
) -> dict[str, str]:
    """Redact authentication and session headers with `credential_placeholder`."""
    if not headers:
        return {}
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k)
        if key_str.strip().lower() in SENSITIVE_HEADER_NAMES:
            redacted[key_str] = credential_placeholder
        else:
            redacted[key_str] = redact_sensitive_text(str(v))
    return redacted


def sanitize_structured_payload(
    payload: Any,
    *,
    credential_placeholder: str = "[REDACTED_CREDENTIAL]",
    _under_sensitive_key: bool = False,
) -> Any:
    """Recursively sanitize dicts, lists, tuples, sets, and strings for safe persistence and logging."""
    if payload is None:
        return {} if not _under_sensitive_key else credential_placeholder
    if isinstance(payload, (int, float, bool)):
        return credential_placeholder if _under_sensitive_key else payload
    if isinstance(payload, str):
        if _under_sensitive_key:
            return credential_placeholder
        return redact_sensitive_text(payload)
    if isinstance(payload, (list, tuple, set)):
        return [
            sanitize_structured_payload(
                item,
                credential_placeholder=credential_placeholder,
                _under_sensitive_key=_under_sensitive_key,
            )
            for item in payload
        ]
    if isinstance(payload, dict):
        sanitized_dict: dict[str, Any] = {}
        for k, v in payload.items():
            key_str = str(k)
            key_lower = key_str.strip().lower()
            if key_lower == "headers" and isinstance(v, dict):
                sanitized_dict[key_str] = redact_headers_dict(
                    v, credential_placeholder=credential_placeholder
                )
            elif is_sensitive_dict_key(key_lower):
                if isinstance(v, (dict, list, tuple, set)):
                    sanitized_dict[key_str] = sanitize_structured_payload(
                        v,
                        credential_placeholder=credential_placeholder,
                        _under_sensitive_key=True,
                    )
                else:
                    sanitized_dict[key_str] = credential_placeholder
            else:
                sanitized_dict[key_str] = sanitize_structured_payload(
                    v,
                    credential_placeholder=credential_placeholder,
                    _under_sensitive_key=_under_sensitive_key,
                )
        return sanitized_dict
    return (
        credential_placeholder
        if _under_sensitive_key
        else redact_sensitive_text(str(payload))
    )


class SecretRedactingFilter(logging.Filter):
    """Logging filter that guarantees credentials are scrubbed before emission."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = sanitize_structured_payload(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    sanitize_structured_payload(a) if isinstance(a, (str, dict, list, tuple)) else a
                    for a in record.args
                )
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line structured JSON with ISO-8601 UTC timestamps."""

    def format(self, record: logging.LogRecord) -> str:
        message = redact_sensitive_text(record.getMessage())
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        if record.exc_info:
            payload["exception"] = redact_sensitive_text(
                self.formatException(record.exc_info)
            )
        return json.dumps(payload, ensure_ascii=True)


def configure_logging(log_level: str = "INFO") -> None:
    """Configure root and application loggers with secret redaction."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid duplicate handlers on reload
    root_logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(SecretRedactingFilter())
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(handler)
