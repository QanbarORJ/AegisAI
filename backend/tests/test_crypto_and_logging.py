"""Phase 2 Verification: Envelope Encryption (AES-256-GCM + AAD), Secret Redaction, and Audit Logging."""

import pytest
from sqlalchemy.orm import Session

from app.core.audit import record_audit_event
from app.core.crypto import (
    decrypt_credentials,
    encrypt_credentials,
    generate_credential_preview,
)
from app.core.exceptions import CredentialDecryptionError
from app.core.logging import redact_sensitive_text


def test_credential_encryption_roundtrip_and_preview() -> None:
    """Verify AES-256-GCM encryption/decryption round-trip and safe masked preview generation."""
    org_id = "org-alpha-1111"
    raw_secrets = {
        "api_key": "sk-proj-9f8a7b6c5d4e3f2a1b0c9d8e7f6a",
        "tenant_b_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    }

    token = encrypt_credentials(raw_secrets, organization_id=org_id)
    assert token.startswith("v1:")
    assert "sk-proj-" not in token

    decrypted = decrypt_credentials(token, organization_id=org_id)
    assert decrypted == raw_secrets

    preview = generate_credential_preview(raw_secrets)
    assert preview == "sk-pro****...7f6a"
    assert "9f8a7b6c5d4e3f2a1b0c" not in preview


def test_credential_encryption_blocks_cross_tenant_aad_mismatch_and_tampering() -> None:
    """Ciphertext encrypted for Organization A must fail authentication when decrypted under Organization B."""
    secrets = {"api_key": "sk-proj-supersecretproductionkey12345"}
    ciphertext = encrypt_credentials(secrets, organization_id="org-tenant-A")

    # Cross-tenant decryption attempt must raise CredentialDecryptionError
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(ciphertext, organization_id="org-tenant-B")

    # Wrong master key must raise CredentialDecryptionError
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(
            ciphertext,
            organization_id="org-tenant-A",
            master_key="wrong-master-key-0000000000000000000000000000",
        )

    # Tampered ciphertext must raise CredentialDecryptionError
    tampered = ciphertext[:-4] + ("AAAA" if ciphertext[-4:] != "AAAA" else "BBBB")
    with pytest.raises(CredentialDecryptionError):
        decrypt_credentials(tampered, organization_id="org-tenant-A")


def test_structured_logging_and_audit_service_scrub_secrets(
    db_session: Session, multi_tenant_seed: dict[str, object]
) -> None:
    """Verify redact_sensitive_text and record_audit_event scrub Bearer tokens, OpenAI keys, AWS keys, and JWTs."""
    raw_log = (
        "Failed request with Authorization: Bearer sk-proj-1234567890abcdefghij "
        "and aws key AKIAIOSFODNN7EXAMPLE and token "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    sanitized = redact_sensitive_text(raw_log)
    assert "sk-proj-1234567890abcdefghij" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in sanitized
    assert "[REDACTED" in sanitized

    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_admin = multi_tenant_seed["alpha_admin"]

    audit_entry = record_audit_event(
        db_session,
        organization_id=org_alpha.id,
        user_id=alpha_admin.id,
        action="TARGET_CREDENTIAL_ROTATED",
        resource_type="TARGET_PROFILE",
        resource_id="target-123",
        details={
            "api_key": "sk-proj-rawsecretthatmustneverbepersisted12345",
            "credential_preview": "sk-pro****...2345",
            "scope_attestation_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015",
            "note": "Header Authorization: Bearer secret-bearer-token-99999",
        },
    )
    assert audit_entry.details_json["api_key"] == "[REDACTED]"
    assert audit_entry.details_json["credential_preview"] == "sk-pro****...2345"
    assert (
        audit_entry.details_json["scope_attestation_hash"]
        == "sha256:9f86d081884c7d659a2feaa0c55ad015"
    )
    assert "secret-bearer-token-99999" not in audit_entry.details_json["note"]
