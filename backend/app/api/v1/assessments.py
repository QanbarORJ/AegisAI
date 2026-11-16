"""Tenant-Isolated Assessments API routes enforcing Scope Attestation, RBAC, and Orchestrator Execution."""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleEnum,
    TenantContext,
    get_current_tenant_context,
    get_db,
    get_tenant_scoped_entity,
    require_roles,
)
from app.engine.orchestrator import AssessmentOrchestrator
from app.models.assessment import Assessment, AssessmentStatusEnum
from app.models.target import TargetProfile
from app.schemas.assessment import (
    AssessmentCreateRequest,
    AssessmentDetailResponse,
    AssessmentResponse,
)

router = APIRouter(prefix="/assessments", tags=["Security Assessments"])


@router.post(
    "",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and scope-attest a new Security Assessment",
)
def create_assessment(
    payload: AssessmentCreateRequest,
    request: Request,
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> AssessmentResponse:
    """Create a tenant-scoped Assessment, verify Scope Attestation, and transition to QUEUED."""
    target = get_tenant_scoped_entity(
        db, TargetProfile, payload.target_profile_id, ctx.organization_id
    )

    assessment = Assessment(
        organization_id=ctx.organization_id,
        target_profile_id=target.id,
        initiated_by_user_id=ctx.user_id,
        name=payload.name.strip(),
        selected_modules=[m.strip().upper() for m in payload.selected_modules if m.strip()],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation=payload.scope_attestation.model_dump(),
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    client_ip = request.client.host if request.client else "127.0.0.1"
    orchestrator = AssessmentOrchestrator(db)
    orchestrator.attest_and_queue_assessment(
        assessment,
        target,
        attested_by_user_id=ctx.user_id,
        client_ip=client_ip,
    )
    return AssessmentResponse.model_validate(assessment)


@router.post(
    "/{assessment_id}/run",
    response_model=AssessmentDetailResponse,
    summary="Execute a queued Security Assessment through the AssessmentOrchestrator",
)
async def run_assessment_endpoint(
    assessment_id: str,
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> AssessmentDetailResponse:
    """Execute the full assessment lifecycle for a tenant-scoped Assessment."""
    assessment = get_tenant_scoped_entity(
        db, Assessment, assessment_id, ctx.organization_id
    )
    orchestrator = AssessmentOrchestrator(db)
    completed = await orchestrator.run_assessment(assessment.id)
    return AssessmentDetailResponse.model_validate(completed)


@router.get(
    "",
    response_model=list[AssessmentResponse],
    summary="List Security Assessments scoped to the caller's Organization",
)
def list_assessments(
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[AssessmentResponse]:
    """List Assessments belonging to the current tenant (accessible to ORG_ADMIN, SECURITY_ENGINEER, VIEWER)."""
    items = (
        db.query(Assessment)
        .filter(Assessment.organization_id == ctx.organization_id)
        .order_by(Assessment.created_at.desc())
        .all()
    )
    return [AssessmentResponse.model_validate(a) for a in items]


@router.get(
    "/{assessment_id}",
    response_model=AssessmentDetailResponse,
    summary="Retrieve full Assessment details, test execution matrix, and findings",
)
def get_assessment(
    assessment_id: str,
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> AssessmentDetailResponse:
    """Retrieve a specific Assessment by ID with strict tenant isolation enforcement."""
    assessment = get_tenant_scoped_entity(
        db, Assessment, assessment_id, ctx.organization_id
    )
    return AssessmentDetailResponse.model_validate(assessment)
