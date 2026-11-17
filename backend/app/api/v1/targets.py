"""Tenant-Isolated TargetProfile API routes enforcing SSRF Guard, Envelope Encryption, and RBAC."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleEnum,
    TenantContext,
    get_db,
    get_tenant_scoped_entity,
    require_roles,
)
from app.core.audit import record_audit_event
from app.core.crypto import encrypt_credentials, generate_credential_preview
from app.core.ssrf_guard import validate_target_url
from app.models.target import IntegrationModeEnum, TargetProfile
from app.schemas.target import TargetProfileCreateRequest, TargetProfileResponse

router = APIRouter(prefix="/targets", tags=["Target Profiles"])


@router.post(
    "",
    response_model=TargetProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new TargetProfile with SSRF validation and AES-256-GCM credential encryption",
)
def create_target_profile(
    payload: TargetProfileCreateRequest,
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> TargetProfileResponse:
    """Create a tenant-scoped TargetProfile after validating SSRF boundaries and encrypting secrets."""
    should_resolve_dns = payload.integration_mode not in (
        IntegrationModeEnum.SIMULATOR,
        IntegrationModeEnum.CONFIG_ONLY,
    )
    validate_target_url(
        payload.endpoint_url,
        allowed_hosts=payload.allowed_hosts,
        resolve_dns=should_resolve_dns,
    )

    encrypted_creds: str | None = None
    cred_preview: str | None = None
    if payload.credentials:
        encrypted_creds = encrypt_credentials(
            payload.credentials,
            organization_id=ctx.organization_id,
        )
        cred_preview = generate_credential_preview(payload.credentials)

    target = TargetProfile(
        organization_id=ctx.organization_id,
        name=payload.name.strip(),
        architecture_type=payload.architecture_type.value,
        integration_mode=payload.integration_mode.value,
        endpoint_url=payload.endpoint_url.strip(),
        allowed_hosts=[h.strip().lower() for h in payload.allowed_hosts if h.strip()],
        auth_type=payload.auth_type.value,
        encrypted_credentials=encrypted_creds,
        credential_preview=cred_preview,
        request_template=payload.request_template,
        architecture_manifest=payload.architecture_manifest,
        rag_harness_config=payload.rag_harness_config,
        agent_harness_config=payload.agent_harness_config,
        rate_limit_rps=min(payload.rate_limit_rps, ctx.organization.max_rps_limit),
        timeout_seconds=payload.timeout_seconds,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    record_audit_event(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        action="TARGET_PROFILE_CREATED",
        resource_type="TARGET_PROFILE",
        resource_id=target.id,
        details={
            "name": target.name,
            "endpoint_url": target.endpoint_url,
            "allowed_hosts": target.allowed_hosts,
            "integration_mode": target.integration_mode,
            "credential_preview": cred_preview,
        },
    )
    return TargetProfileResponse.model_validate(target)


@router.get(
    "",
    response_model=list[TargetProfileResponse],
    summary="List TargetProfiles scoped to the caller's Organization (ORG_ADMIN & SECURITY_ENGINEER)",
)
def list_target_profiles(
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> list[TargetProfileResponse]:
    """List TargetProfiles belonging to the current tenant (VIEWER prohibited per SECURITY_DESIGN.md Section 5)."""
    targets = (
        db.query(TargetProfile)
        .filter(TargetProfile.organization_id == ctx.organization_id)
        .order_by(TargetProfile.created_at.desc())
        .all()
    )
    return [TargetProfileResponse.model_validate(t) for t in targets]


@router.get(
    "/{target_id}",
    response_model=TargetProfileResponse,
    summary="Retrieve a specific TargetProfile with strict tenant isolation enforcement",
)
def get_target_profile(
    target_id: str,
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> TargetProfileResponse:
    """Retrieve a TargetProfile by ID, raising 404 TenantIsolationError if owned by another tenant."""
    target = get_tenant_scoped_entity(
        db, TargetProfile, target_id, ctx.organization_id
    )
    return TargetProfileResponse.model_validate(target)
