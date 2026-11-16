"""Security Frameworks & Tenant Compliance Posture API routes (Phase 6)."""

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    TenantContext,
    get_current_tenant_context,
    get_db,
    get_tenant_scoped_entity,
)
from app.core.exceptions import ResourceNotFoundError
from app.engine.framework_mapper import ensure_knowledge_base_seeded
from app.engine.report_generator import extract_finding_framework_mappings
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.framework import FrameworkControl, SecurityFramework
from app.schemas.framework import (
    ComplianceControlImpactResponse,
    FrameworkComplianceSummaryItem,
    FrameworkControlResponse,
    SecurityFrameworkDetailResponse,
    SecurityFrameworkSummaryResponse,
    TenantCompliancePostureResponse,
)

router = APIRouter(prefix="/frameworks", tags=["Security Frameworks & Compliance"])

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@router.get(
    "",
    response_model=list[SecurityFrameworkSummaryResponse],
    summary="List all authoritative Security & Governance Frameworks in the Knowledge Base",
)
def list_frameworks(
    _ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> list[SecurityFrameworkSummaryResponse]:
    """Return all seeded security frameworks with their control counts."""
    ensure_knowledge_base_seeded(db)
    frameworks = db.query(SecurityFramework).order_by(SecurityFramework.id.asc()).all()
    results: list[SecurityFrameworkSummaryResponse] = []
    for fw in frameworks:
        ctrl_count = (
            db.query(FrameworkControl)
            .filter(FrameworkControl.framework_id == fw.id)
            .count()
        )
        results.append(
            SecurityFrameworkSummaryResponse(
                id=fw.id,
                name=fw.name,
                version=fw.version,
                publisher=fw.publisher,
                release_date=fw.release_date,
                description=fw.description,
                official_url=fw.official_url,
                control_count=ctrl_count,
            )
        )
    return results


@router.get(
    "/compliance/summary",
    response_model=TenantCompliancePostureResponse,
    summary="Retrieve tenant-scoped framework compliance posture and control impact summary",
)
def get_compliance_summary(
    assessment_id: str | None = Query(
        default=None,
        description="Optional Assessment ID to scope the compliance posture summary.",
    ),
    ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> TenantCompliancePostureResponse:
    """Compute per-framework compliance impact strictly scoped to the caller's Organization."""
    ensure_knowledge_base_seeded(db)

    assessment: Assessment | None = None
    if assessment_id is not None:
        assessment = get_tenant_scoped_entity(
            db, Assessment, assessment_id, ctx.organization_id
        )

    findings_query = db.query(Finding).filter(
        Finding.organization_id == ctx.organization_id
    )
    if assessment is not None:
        findings_query = findings_query.filter(Finding.assessment_id == assessment.id)

    findings = findings_query.order_by(Finding.avss_score.desc()).all()

    # Load baseline frameworks (prefer assessment's historical KB snapshot if assessment is specified)
    fw_catalog: dict[str, dict[str, Any]] = {}
    if assessment is not None and isinstance(assessment.summary_metrics, dict):
        kb_snapshot = assessment.summary_metrics.get("framework_kb_snapshot")
        snap_items: list[Any] = []
        if isinstance(kb_snapshot, dict):
            snap_items = list(kb_snapshot.values())
        elif isinstance(kb_snapshot, list):
            snap_items = kb_snapshot
        for snap in snap_items:
            if isinstance(snap, dict) and snap.get("id"):
                fw_id = str(snap["id"])
                ctrl_count = (
                    db.query(FrameworkControl)
                    .filter(FrameworkControl.framework_id == fw_id)
                    .count()
                )
                fw_catalog[fw_id] = {
                    "framework_id": fw_id,
                    "name": str(snap.get("name", fw_id)),
                    "version": str(snap.get("version", "1.0")),
                    "publisher": str(snap.get("publisher", "")),
                    "official_url": str(snap.get("official_url", "")),
                    "total_controls": ctrl_count,
                }

    if not fw_catalog:
        for fw in db.query(SecurityFramework).order_by(SecurityFramework.id.asc()).all():
            ctrl_count = (
                db.query(FrameworkControl)
                .filter(FrameworkControl.framework_id == fw.id)
                .count()
            )
            fw_catalog[fw.id] = {
                "framework_id": fw.id,
                "name": fw.name,
                "version": fw.version,
                "publisher": fw.publisher,
                "official_url": fw.official_url,
                "total_controls": ctrl_count,
            }

    # Track per-framework relationship counts and control impact
    fw_direct_findings: dict[str, set[str]] = {fw_id: set() for fw_id in fw_catalog}
    fw_related_findings: dict[str, set[str]] = {fw_id: set() for fw_id in fw_catalog}
    fw_supporting_findings: dict[str, set[str]] = {fw_id: set() for fw_id in fw_catalog}
    fw_controls_impact: dict[str, dict[str, dict[str, Any]]] = {
        fw_id: {} for fw_id in fw_catalog
    }

    for finding in findings:
        mappings = extract_finding_framework_mappings(finding, db)
        for m in mappings:
            fw_id = str(m.get("framework_id", "UNKNOWN"))
            if fw_id not in fw_catalog:
                fw_catalog[fw_id] = {
                    "framework_id": fw_id,
                    "name": str(m.get("framework_name", fw_id)),
                    "version": str(m.get("framework_version", "1.0")),
                    "publisher": str(m.get("publisher", "Unknown")),
                    "official_url": str(m.get("official_reference_url", "https://owasp.org/")),
                    "total_controls": 0,
                }
                fw_direct_findings[fw_id] = set()
                fw_related_findings[fw_id] = set()
                fw_supporting_findings[fw_id] = set()
                fw_controls_impact[fw_id] = {}

            rel_type = str(m.get("mapping_type", "DIRECT")).upper()
            if rel_type == "DIRECT":
                fw_direct_findings[fw_id].add(finding.id)
            elif rel_type == "RELATED":
                fw_related_findings[fw_id].add(finding.id)
            else:
                fw_supporting_findings[fw_id].add(finding.id)

            ctrl_id = str(m.get("control_id", ""))
            ctrl_bucket = fw_controls_impact[fw_id].get(ctrl_id)
            if ctrl_bucket is None:
                ctrl_bucket = {
                    "control_id": ctrl_id,
                    "title": str(m.get("title", ctrl_id)),
                    "category": str(m.get("category", "")),
                    "official_reference_url": str(
                        m.get("official_reference_url", "https://owasp.org/")
                    ),
                    "finding_ids": set(),
                    "highest_severity": finding.severity,
                    "relationship_types": set(),
                }
                fw_controls_impact[fw_id][ctrl_id] = ctrl_bucket

            ctrl_bucket["finding_ids"].add(finding.id)
            ctrl_bucket["relationship_types"].add(rel_type)
            if _SEVERITY_RANK.get(finding.severity, 0) > _SEVERITY_RANK.get(
                ctrl_bucket["highest_severity"], 0
            ):
                ctrl_bucket["highest_severity"] = finding.severity

    framework_items: list[FrameworkComplianceSummaryItem] = []
    for fw_id, meta in fw_catalog.items():
        controls_out: list[ComplianceControlImpactResponse] = []
        for ctrl_id in sorted(fw_controls_impact.get(fw_id, {}).keys()):
            c_data = fw_controls_impact[fw_id][ctrl_id]
            controls_out.append(
                ComplianceControlImpactResponse(
                    control_id=c_data["control_id"],
                    title=c_data["title"],
                    category=c_data["category"],
                    official_reference_url=c_data["official_reference_url"],
                    finding_count=len(c_data["finding_ids"]),
                    highest_severity=c_data["highest_severity"],
                    relationship_types=sorted(c_data["relationship_types"]),
                )
            )
        framework_items.append(
            FrameworkComplianceSummaryItem(
                framework_id=fw_id,
                name=meta["name"],
                version=meta["version"],
                publisher=meta["publisher"],
                official_url=meta["official_url"],
                total_controls=max(meta["total_controls"], len(controls_out)),
                affected_controls_count=len(controls_out),
                direct_findings_count=len(fw_direct_findings.get(fw_id, set())),
                related_findings_count=len(fw_related_findings.get(fw_id, set())),
                supporting_findings_count=len(fw_supporting_findings.get(fw_id, set())),
                affected_controls=controls_out,
            )
        )

    confirmed_count = sum(1 for f in findings if f.is_confirmed)
    suspected_count = sum(1 for f in findings if not f.is_confirmed)

    return TenantCompliancePostureResponse(
        organization_id=ctx.organization_id,
        assessment_id=assessment.id if assessment else None,
        total_findings_evaluated=len(findings),
        confirmed_findings_count=confirmed_count,
        suspected_findings_count=suspected_count,
        frameworks=framework_items,
    )


@router.get(
    "/{framework_id}",
    response_model=SecurityFrameworkDetailResponse,
    summary="Retrieve a specific Security Framework and its full catalog of controls",
)
def get_framework_detail(
    framework_id: str,
    _ctx: TenantContext = Depends(get_current_tenant_context),
    db: Session = Depends(get_db),
) -> SecurityFrameworkDetailResponse:
    """Return a specific SecurityFramework and all associated FrameworkControl records."""
    ensure_knowledge_base_seeded(db)
    fw = (
        db.query(SecurityFramework)
        .filter(SecurityFramework.id == framework_id)
        .first()
    )
    if fw is None:
        raise ResourceNotFoundError("SecurityFramework", framework_id)

    controls = (
        db.query(FrameworkControl)
        .filter(FrameworkControl.framework_id == fw.id)
        .order_by(FrameworkControl.control_id.asc())
        .all()
    )
    return SecurityFrameworkDetailResponse(
        id=fw.id,
        name=fw.name,
        version=fw.version,
        publisher=fw.publisher,
        release_date=fw.release_date,
        description=fw.description,
        official_url=fw.official_url,
        control_count=len(controls),
        controls=[FrameworkControlResponse.model_validate(c) for c in controls],
    )
