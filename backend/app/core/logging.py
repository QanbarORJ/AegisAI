"""Structured logging with automatic credential and secret redaction (Mitigates TM-05)."""

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

# High-entropy secret and token patterns that must never appear in plaintext logs
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)(authorization\s*[:=]\s*['\"]?bearer\s+)[a-zA-Z0-9_\-\.~+/]+=*"),
        r"\1[REDACTED_BEARER_TOKEN]",
    ),
    (
        re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[a-zA-Z0-9_\-]{12,}\b"),
        "sk-[REDACTED_API_KEY]",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AKIA[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b"),
        "eyJ[REDACTED_JWT_TOKEN]",
    ),
    (
        re.compile(r"(?i)(x-api-key|api_key|apikey|password|secret)\s*[:=]\s*['\"]?([^\s,'\"\}]+)"),
        r"\1=[REDACTED_SECRET]",
    ),
]


def redact_sensitive_text(text: str) -> str:
    """Redact API keys, Bearer tokens, JWTs, and secret headers from arbitrary strings."""
    if not text:
        return text
    sanitized = text
    for pattern, replacement in _SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class SecretRedactingFilter(logging.Filter):
    """Logging filter that guarantees credentials are scrubbed before emission."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_sensitive_text(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_sensitive_text(str(a)) if isinstance(a, str) else a
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
