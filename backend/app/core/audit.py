"""Immutable Audit Logging Service (SECURITY_DESIGN.md Section 2 & DATABASE_SCHEMA.md Section 2.1)."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import redact_sensitive_text
from app.models.audit import AuditLog

logger = logging.getLogger("aegis.audit")


def _sanitize_audit_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Ensure no credentials or raw secrets are ever persisted in audit_logs.details_json."""
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        lower_key = key.lower()
        if any(
            secret_word in lower_key
            for secret_word in ("password", "secret", "token", "api_key", "credential")
        ) and lower_key not in ("credential_preview", "scope_attestation_hash"):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, str):
            sanitized[key] = redact_sensitive_text(value)
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_audit_dict(value)
        else:
            sanitized[key] = value
    return sanitized


def record_audit_event(
    db: Session,
    *,
    organization_id: str,
    user_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    """Create and persist an immutable, secret-redacted AuditLog entry."""
    safe_details = _sanitize_audit_dict(details or {})
    entry = AuditLog(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details_json=safe_details,
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    logger.info(
        "Audit event recorded: action=%s resource_type=%s resource_id=%s org=%s user=%s",
        action,
        resource_type,
        resource_id,
        organization_id,
        user_id,
    )
    return entry
