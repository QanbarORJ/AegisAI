"""Tenant-Isolated Security Findings API routes (Phase 6)."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    TenantContext,
    get_current_tenant_context,
    get_db,
    get_tenant_scoped_entity,
)
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.schemas.assessment import FindingResponse

router = APIRouter(prefix="/findings", tags=["Security Findings"])


@router.get(
    "",
    response_model=list[FindingResponse],
    summary="List Security Findings scoped to the caller's Organization",
)
def list_findings(
    assessment_id: str | None = Query(
        default=None, description="Optional Assessment ID filter."
    ),
    severity: str | None = Query(
        default=None, description="Optional AVSS severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)."
    ),
    module: str | None = Query(
        default=None, description="Optional module filter (LLM, RAG, AGENT, CONFIG)."
    ),
    is_confirmed: bool | None = Query(
        default=None, description="Optional confirmation status filter (true=FAIL, false=NEEDS_REVIEW)."
    ),
    confidence: str | None = Query(
        default=None, description="Optional detection confidence filter (HIGH, MEDIUM, LOW)."
    ),
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    """List findings strictly scoped to the caller's Organization with optional filters."""
    if assessment_id is not None:
        get_tenant_scoped_entity(
            db, Assessment, assessment_id, ctx.organization_id
        )

    query = db.query(Finding).filter(Finding.organization_id == ctx.organization_id)
    if assessment_id is not None:
        query = query.filter(Finding.assessment_id == assessment_id)
    if severity is not None:
        query = query.filter(Finding.severity == severity.strip().upper())
    if module is not None:
        query = query.filter(Finding.module == module.strip().upper())
    if is_confirmed is not None:
        query = query.filter(Finding.is_confirmed == is_confirmed)
    if confidence is not None:
        query = query.filter(Finding.confidence == confidence.strip().upper())

    findings = query.order_by(
        Finding.avss_score.desc(), Finding.created_at.desc()
    ).all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Retrieve a specific tenant-scoped Security Finding with evidence, mappings, and remediation",
)
def get_finding(
    finding_id: str,
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> FindingResponse:
    """Retrieve a specific Finding by ID with strict multi-tenant isolation enforcement."""
    finding = get_tenant_scoped_entity(
        db, Finding, finding_id, ctx.organization_id
    )
    return FindingResponse.model_validate(finding)
