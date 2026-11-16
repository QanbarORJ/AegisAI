"""Domain exception hierarchy for AegisAI."""

from typing import Any


class AegisError(Exception):
    """Base exception for all AegisAI domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "AEGIS_ERROR",
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class AuthenticationError(AegisError):
    """Raised when user credentials or JWT tokens are invalid or expired."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message=message, code="AUTHENTICATION_FAILED", status_code=401)


class AuthorizationError(AegisError):
    """Raised when a user lacks required RBAC permissions for an operation."""

    def __init__(
        self, message: str = "Insufficient permissions for this operation"
    ) -> None:
        super().__init__(message=message, code="FORBIDDEN_OPERATION", status_code=403)


class TenantIsolationError(AegisError):
    """Raised on any cross-tenant access attempt."""

    def __init__(
        self, message: str = "Resource not found within current organization scope"
    ) -> None:
        super().__init__(message=message, code="TENANT_SCOPE_VIOLATION", status_code=404)


class ResourceNotFoundError(AegisError):
    """Raised when a requested entity does not exist."""

    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"{resource} '{identifier}' was not found.",
            code="RESOURCE_NOT_FOUND",
            status_code=404,
        )


class SSRFBlockedError(AegisError):
    """Raised when a target URL or resolved IP violates SSRF network boundary rules."""

    def __init__(self, message: str, blocked_target: str | None = None) -> None:
        super().__init__(
            message=message,
            code="SSRF_BOUNDARY_BLOCKED",
            status_code=422,
            details={"blocked_target": blocked_target} if blocked_target else {},
        )


class ScopeViolationError(AegisError):
    """Raised when active testing is attempted without valid scope attestation or host authorization."""

    def __init__(self, message: str) -> None:
        super().__init__(
            message=message,
            code="SCOPE_AUTHORIZATION_VIOLATION",
            status_code=422,
        )


class CredentialDecryptionError(AegisError):
    """Raised when target credential decryption fails or AAD tenant context mismatches."""

    def __init__(
        self, message: str = "Failed to decrypt target credentials for tenant context"
    ) -> None:
        super().__init__(
            message=message,
            code="CREDENTIAL_DECRYPTION_ERROR",
            status_code=500,
        )
