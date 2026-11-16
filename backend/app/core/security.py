"""Authentication, Password Hashing (Bcrypt), JWT Token Management, and Multi-Tenant RBAC Dependencies."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, TypeVar

import bcrypt
import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    TenantIsolationError,
)
from app.db.session import get_db

if TYPE_CHECKING:
    from app.models.user import Organization, User

T = TypeVar("T")

bearer_scheme = HTTPBearer(auto_error=False)


class RoleEnum(StrEnum):
    """Canonical RBAC roles standardized across AegisAI (SECURITY_DESIGN.md Section 5)."""

    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    VIEWER = "VIEWER"


@dataclass(frozen=True)
class TenantContext:
    """Immutable authenticated multi-tenant execution context for the current request."""

    user_id: str
    organization_id: str
    email: str
    role: RoleEnum
    user: "User"
    organization: "Organization"


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt with automatic salt generation."""
    password_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False


def create_access_token(
    *,
    user_id: str,
    organization_id: str,
    email: str,
    role: RoleEnum | str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token bound to user_id, organization_id, and role."""
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + (
        expires_delta
        or timedelta(minutes=settings.aegis_access_token_expire_minutes)
    )
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "org_id": str(organization_id),
        "email": email,
        "role": str(role),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(
        payload,
        settings.aegis_jwt_secret_key,
        algorithm=settings.aegis_jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token."""
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.aegis_jwt_secret_key,
            algorithms=[settings.aegis_jwt_algorithm],
        )
        if not payload.get("sub") or not payload.get("org_id"):
            raise AuthenticationError("Invalid token claims: missing subject or tenant scope.")
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Access token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid authentication token.") from exc


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> "User":
    """FastAPI dependency that validates the Bearer JWT and loads the active User."""
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Missing Bearer authentication token.")

    payload = decode_access_token(credentials.credentials)
    user_id = str(payload["sub"])
    org_id = str(payload["org_id"])

    from app.models.user import User

    user = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == org_id)
        .first()
    )
    if user is None:
        raise AuthenticationError("Authenticated user no longer exists in tenant scope.")
    if not user.is_active:
        raise AuthenticationError("User account is deactivated.")
    return user


def get_current_tenant_context(
    current_user: "User" = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TenantContext:
    """FastAPI dependency returning the verified TenantContext (User + Organization)."""
    from app.models.user import Organization

    organization = (
        db.query(Organization)
        .filter(Organization.id == current_user.organization_id)
        .first()
    )
    if organization is None:
        raise AuthenticationError("Organization associated with token does not exist.")

    try:
        role_enum = RoleEnum(current_user.role)
    except ValueError as exc:
        raise AuthorizationError(f"Unrecognized user role '{current_user.role}'.") from exc

    return TenantContext(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        email=current_user.email,
        role=role_enum,
        user=current_user,
        organization=organization,
    )


def require_roles(*allowed_roles: RoleEnum | str) -> Callable[[TenantContext], TenantContext]:
    """Dependency factory enforcing Role-Based Access Control (RBAC)."""
    normalized_roles = {RoleEnum(r) for r in allowed_roles}

    def _role_checker(
        ctx: TenantContext = Depends(get_current_tenant_context),
    ) -> TenantContext:
        if ctx.role not in normalized_roles:
            allowed_str = ", ".join(sorted(r.value for r in normalized_roles))
            raise AuthorizationError(
                f"Role '{ctx.role.value}' is not permitted for this operation. Required: [{allowed_str}]."
            )
        return ctx

    return _role_checker


def get_tenant_scoped_entity(
    db: Session,
    model: type[T],
    entity_id: str,
    organization_id: str,
) -> T:
    """Fetch an entity by primary key strictly scoped to `organization_id` (prevents IDOR / TM-04)."""
    entity = (
        db.query(model)
        .filter(
            model.id == entity_id,
            model.organization_id == organization_id,
        )
        .first()
    )
    if entity is None:
        raise TenantIsolationError(
            f"{model.__name__} '{entity_id}' was not found within current organization scope."
        )
    return entity
