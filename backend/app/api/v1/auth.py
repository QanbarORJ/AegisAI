"""Authentication, Multi-Tenant Organization Bootstrap, User Management, and Audit Log API routes."""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleEnum,
    TenantContext,
    get_current_tenant_context,
    get_db,
    require_roles,
)
from app.core.audit import record_audit_event
from app.core.config import get_settings
from app.core.exceptions import AegisError, AuthenticationError
from app.core.security import create_access_token, hash_password, verify_password
from app.models.audit import AuditLog
from app.models.user import Organization, User
from app.schemas.auth import (
    AuditLogResponse,
    LoginRequest,
    OrganizationResponse,
    RegisterOrganizationRequest,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bootstrap a new Organization tenant and initial ORG_ADMIN user",
)
def register_organization(
    payload: RegisterOrganizationRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Create a new tenant Organization and its founding ORG_ADMIN User."""
    normalized_email = payload.email.strip().lower()
    normalized_slug = payload.organization_slug.strip().lower()

    existing_org = (
        db.query(Organization).filter(Organization.slug == normalized_slug).first()
    )
    if existing_org is not None:
        raise AegisError(
            message=f"Organization slug '{normalized_slug}' is already registered.",
            code="ORGANIZATION_SLUG_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )

    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user is not None:
        raise AegisError(
            message=f"User email '{normalized_email}' is already registered.",
            code="USER_EMAIL_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )

    organization = Organization(
        name=payload.organization_name.strip(),
        slug=normalized_slug,
    )
    db.add(organization)
    db.flush()

    admin_user = User(
        organization_id=organization.id,
        email=normalized_email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=RoleEnum.ORG_ADMIN.value,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(organization)
    db.refresh(admin_user)

    record_audit_event(
        db,
        organization_id=organization.id,
        user_id=admin_user.id,
        action="ORGANIZATION_REGISTERED",
        resource_type="ORGANIZATION",
        resource_id=organization.id,
        details={
            "organization_slug": organization.slug,
            "admin_email": admin_user.email,
            "client_ip": request.client.host if request.client else "unknown",
        },
    )

    settings = get_settings()
    token = create_access_token(
        user_id=admin_user.id,
        organization_id=organization.id,
        email=admin_user.email,
        role=RoleEnum.ORG_ADMIN,
    )
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.aegis_access_token_expire_minutes,
        user=UserResponse.model_validate(admin_user),
        organization=OrganizationResponse.model_validate(organization),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user credentials and issue a tenant-scoped JWT access token",
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Verify email and bcrypt password hash and return a signed JWT."""
    normalized_email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise AuthenticationError("Invalid email or password.")

    if not user.is_active:
        raise AuthenticationError("User account is deactivated.")

    organization = (
        db.query(Organization).filter(Organization.id == user.organization_id).first()
    )
    if organization is None:
        raise AuthenticationError("Organization associated with user was not found.")

    record_audit_event(
        db,
        organization_id=organization.id,
        user_id=user.id,
        action="USER_LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=user.id,
        details={
            "email": user.email,
            "role": user.role,
            "client_ip": request.client.host if request.client else "unknown",
        },
    )

    settings = get_settings()
    token = create_access_token(
        user_id=user.id,
        organization_id=organization.id,
        email=user.email,
        role=user.role,
    )
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.aegis_access_token_expire_minutes,
        user=UserResponse.model_validate(user),
        organization=OrganizationResponse.model_validate(organization),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Return the currently authenticated user profile",
)
def get_me(
    ctx: TenantContext = Depends(get_current_tenant_context),
) -> UserResponse:
    """Return current user scoped to the active JWT tenant context."""
    return UserResponse.model_validate(ctx.user)


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user within the current Organization (ORG_ADMIN only)",
)
def create_organization_user(
    payload: UserCreateRequest,
    ctx: TenantContext = Depends(require_roles(RoleEnum.ORG_ADMIN)),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Allow an ORG_ADMIN to provision users (ORG_ADMIN, SECURITY_ENGINEER, VIEWER) in their tenant."""
    normalized_email = payload.email.strip().lower()
    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing is not None:
        raise AegisError(
            message=f"User email '{normalized_email}' is already registered.",
            code="USER_EMAIL_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )

    new_user = User(
        organization_id=ctx.organization_id,
        email=normalized_email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role.value,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    record_audit_event(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        action="USER_PROVISIONED",
        resource_type="USER",
        resource_id=new_user.id,
        details={
            "provisioned_email": new_user.email,
            "assigned_role": new_user.role,
        },
    )
    return UserResponse.model_validate(new_user)


@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List users belonging to the current Organization tenant",
)
def list_organization_users(
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[UserResponse]:
    """List all users strictly scoped to the caller's `organization_id`."""
    users = (
        db.query(User)
        .filter(User.organization_id == ctx.organization_id)
        .order_by(User.created_at.asc())
        .all()
    )
    return [UserResponse.model_validate(u) for u in users]


@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    summary="Inspect immutable tenant audit logs (ORG_ADMIN only)",
)
def list_organization_audit_logs(
    ctx: TenantContext = Depends(require_roles(RoleEnum.ORG_ADMIN)),
    db: Session = Depends(get_db),
) -> list[AuditLogResponse]:
    """Return immutable AuditLog records strictly scoped to the caller's Organization."""
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == ctx.organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )
    return [AuditLogResponse.model_validate(entry) for entry in logs]
