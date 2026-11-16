"""FastAPI Dependencies for Database Sessions, JWT Authentication, Tenant Isolation, and RBAC."""

from app.core.security import (
    RoleEnum,
    TenantContext,
    bearer_scheme,
    get_current_tenant_context,
    get_current_user,
    get_tenant_scoped_entity,
    require_roles,
)
from app.db.session import get_db

__all__ = [
    "RoleEnum",
    "TenantContext",
    "bearer_scheme",
    "get_current_tenant_context",
    "get_current_user",
    "get_db",
    "get_tenant_scoped_entity",
    "require_roles",
]
