"""Authenticated Envelope Encryption (AES-256-GCM + HKDF-SHA256) for Target Credentials.

Implements SECURITY_DESIGN.md Section 4.1 and mitigates TM-04 / TM-05:
- Derives a 256-bit key from AEGIS_MASTER_ENCRYPTION_KEY via HKDF-SHA256.
- Encrypts target credentials using AES-256-GCM with a random 96-bit nonce.
- Cryptographically binds `organization_id` as Associated Authenticated Data (AAD)
  so ciphertext from one tenant cannot be decrypted under another tenant's context.
"""

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings
from app.core.exceptions import CredentialDecryptionError

_HKDF_SALT = b"aegis-ai-credential-vault-v1-salt"
_HKDF_INFO_PREFIX = b"aegis-ai-aes256gcm-tenant:"


def _derive_tenant_aes_key(master_secret: str, organization_id: str) -> bytes:
    """Derive a tenant-specific 256-bit AES key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO_PREFIX + organization_id.encode("utf-8"),
    )
    return hkdf.derive(master_secret.encode("utf-8"))


def encrypt_credentials(
    credentials_dict: dict[str, Any],
    organization_id: str,
    master_key: str | None = None,
) -> str:
    """Encrypt a dictionary of target credentials using AES-256-GCM with tenant AAD.

    Returns a versioned base64 token: `v1:<base64(nonce + ciphertext_and_tag)>`.
    """
    secret = master_key or get_settings().aegis_master_encryption_key
    key = _derive_tenant_aes_key(secret, str(organization_id))
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit NIST-recommended nonce for GCM
    aad = f"org:{organization_id}".encode()

    plaintext = json.dumps(credentials_dict, sort_keys=True).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return f"v1:{encoded}"


def decrypt_credentials(
    encrypted_token: str,
    organization_id: str,
    master_key: str | None = None,
) -> dict[str, Any]:
    """Decrypt a versioned AES-256-GCM token, verifying tenant AAD integrity."""
    if not encrypted_token or not encrypted_token.startswith("v1:"):
        raise CredentialDecryptionError("Unsupported or corrupted credential token format.")

    secret = master_key or get_settings().aegis_master_encryption_key
    key = _derive_tenant_aes_key(secret, str(organization_id))
    aesgcm = AESGCM(key)
    aad = f"org:{organization_id}".encode()

    try:
        raw = base64.urlsafe_b64decode(encrypted_token[3:].encode("ascii"))
        if len(raw) < 28:  # 12-byte nonce + 16-byte GCM tag minimum
            raise CredentialDecryptionError("Truncated credential ciphertext.")
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise CredentialDecryptionError("Decrypted credential payload is not a JSON object.")
        return data
    except InvalidTag as exc:
        raise CredentialDecryptionError(
            "Credential authentication tag verification failed (invalid key or cross-tenant AAD mismatch)."
        ) from exc
    except Exception as exc:
        if isinstance(exc, CredentialDecryptionError):
            raise
        raise CredentialDecryptionError("Unable to decrypt stored target credentials.") from exc


def generate_credential_preview(credentials_dict: dict[str, Any] | None) -> str | None:
    """Create a safe masked preview (e.g. 'sk-proj-****...9a2f') without exposing secrets."""
    if not credentials_dict:
        return None

    # Look for primary secret field
    candidate = (
        credentials_dict.get("api_key")
        or credentials_dict.get("bearer_token")
        or credentials_dict.get("tenant_a_token")
        or next((str(v) for v in credentials_dict.values() if isinstance(v, str) and v), None)
    )
    if not candidate:
        return "configured (masked)"

    val = candidate.strip()
    if len(val) <= 8:
        return "****"
    prefix = val[:6] if val.startswith(("sk-", "AKIA", "Bearer")) else val[:3]
    suffix = val[-4:]
    return f"{prefix}****...{suffix}"
