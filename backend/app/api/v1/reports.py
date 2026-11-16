"""Tenant-Isolated Assessment Reports & Secure Download API routes (Phase 6)."""

import json

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from app.api.deps import (
    RoleEnum,
    TenantContext,
    get_current_tenant_context,
    get_db,
    get_tenant_scoped_entity,
    require_roles,
)
from app.core.exceptions import AegisError
from app.engine.report_generator import (
    REPORT_SECURITY_HEADERS,
    SUPPORTED_REPORT_FORMATS,
    ReportGenerator,
    build_pdf_bytes_from_report_payload,
)
from app.models.assessment import Assessment, ReportArtifact
from app.schemas.report import (
    ReportCreateRequest,
    ReportDetailResponse,
    ReportSummaryResponse,
)

router = APIRouter(tags=["Enterprise Security Reports"])


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an immutable Enterprise Security Assessment Report (HTML, JSON, or PDF)",
)
def generate_assessment_report(
    assessment_id: str,
    payload: ReportCreateRequest,
    request: Request,
    ctx: TenantContext = Depends(
        require_roles(RoleEnum.ORG_ADMIN, RoleEnum.SECURITY_ENGINEER)
    ),
    db: Session = Depends(get_db),
) -> ReportDetailResponse:
    """Generate and persist a tenant-scoped ReportArtifact for the specified Assessment."""
    fmt = payload.report_format.strip().upper()
    if fmt not in SUPPORTED_REPORT_FORMATS:
        raise AegisError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="UNSUPPORTED_REPORT_FORMAT",
            message=f"Unsupported report format '{payload.report_format}'. Choose from HTML, JSON, PDF.",
        )

    client_ip = request.client.host if request.client else "127.0.0.1"
    generator = ReportGenerator(db)
    report = generator.generate_report(
        assessment_id=assessment_id,
        organization_id=ctx.organization_id,
        generated_by_user_id=ctx.user_id,
        report_format=fmt,
        title=payload.title,
        client_ip=client_ip,
    )
    return ReportDetailResponse.model_validate(report)


@router.get(
    "/assessments/{assessment_id}/reports",
    response_model=list[ReportSummaryResponse],
    summary="List generated reports for a specific tenant-scoped Assessment",
)
def list_assessment_reports(
    assessment_id: str,
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[ReportSummaryResponse]:
    """List ReportArtifacts for a specific Assessment with strict tenant isolation."""
    assessment = get_tenant_scoped_entity(
        db, Assessment, assessment_id, ctx.organization_id
    )
    reports = (
        db.query(ReportArtifact)
        .filter(
            ReportArtifact.organization_id == ctx.organization_id,
            ReportArtifact.assessment_id == assessment.id,
        )
        .order_by(ReportArtifact.created_at.desc())
        .all()
    )
    return [ReportSummaryResponse.model_validate(r) for r in reports]


@router.get(
    "/reports",
    response_model=list[ReportSummaryResponse],
    summary="List all generated reports scoped to the caller's Organization",
)
def list_organization_reports(
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[ReportSummaryResponse]:
    """Return all ReportArtifact summaries belonging to the caller's Organization."""
    reports = (
        db.query(ReportArtifact)
        .filter(ReportArtifact.organization_id == ctx.organization_id)
        .order_by(ReportArtifact.created_at.desc())
        .all()
    )
    return [ReportSummaryResponse.model_validate(r) for r in reports]


@router.get(
    "/reports/{report_id}",
    response_model=ReportDetailResponse,
    summary="Retrieve full report metadata, structured payload, and rendered HTML",
)
def get_report(
    report_id: str,
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> ReportDetailResponse:
    """Retrieve a specific ReportArtifact by ID with strict multi-tenant isolation."""
    report = get_tenant_scoped_entity(
        db, ReportArtifact, report_id, ctx.organization_id
    )
    return ReportDetailResponse.model_validate(report)


@router.get(
    "/reports/{report_id}/download",
    summary="Download a generated ReportArtifact (HTML, JSON, or PDF) with strict CSP headers",
)
def download_report(
    report_id: str,
    format: str | None = Query(
        default=None,
        description="Optional override download format (HTML, JSON, or PDF). Defaults to the report's format.",
    ),
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> Response:
    """Serve a report artifact with locked-down CSP and security headers (TM-02 / Requirement 5)."""
    report = get_tenant_scoped_entity(
        db, ReportArtifact, report_id, ctx.organization_id
    )
    target_format = (format or report.report_format or "HTML").strip().upper()
    if target_format not in SUPPORTED_REPORT_FORMATS:
        raise AegisError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="UNSUPPORTED_REPORT_FORMAT",
            message=f"Unsupported download format '{target_format}'. Choose from HTML, JSON, PDF.",
        )

    headers = dict(REPORT_SECURITY_HEADERS)
    safe_base = f"aegis-report-{report.id[:8]}"

    if target_format == "HTML":
        html_body = report.rendered_html or ReportGenerator(db).render_html_from_payload(
            report.report_payload
        )
        headers["Content-Disposition"] = f'inline; filename="{safe_base}.html"'
        return Response(
            content=html_body,
            media_type="text/html; charset=utf-8",
            headers=headers,
        )

    if target_format == "JSON":
        json_body = json.dumps(report.report_payload, indent=2, sort_keys=False)
        headers["Content-Disposition"] = f'attachment; filename="{safe_base}.json"'
        return Response(
            content=json_body,
            media_type="application/json",
            headers=headers,
        )

    # PDF format
    pdf_bytes = build_pdf_bytes_from_report_payload(report.report_payload)
    headers["Content-Disposition"] = f'attachment; filename="{safe_base}.pdf"'
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=headers,
    )
