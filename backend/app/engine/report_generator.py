"""Enterprise Security Assessment Report Generator (`ReportGenerator`).

Implements ARCHITECTURE.md Section 1, ROADMAP.md Phase 6, THREAT_MODEL.md TM-02/TM-05, and Requirements 4, 5, 6:
1. Generates structured JSON, self-contained print-ready Enterprise HTML, and pure-Python PDF 1.4 reports.
2. Strengthens HTML report security (Requirement 5 & TM-02):
   - Enforces a locked-down Content-Security-Policy (`REPORT_HTML_CSP_POLICY` with `script-src 'none'`,
     `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`).
   - Applies comprehensive output escaping (`html.escape(..., quote=True)`) across every interpolated
     string, JSON evidence block, and code snippet.
   - Validates and sanitizes all reference links (`_safe_href` permitting only `https://` and `http://` schemes).
   - Runs recursive secret/PII sanitization (`sanitize_payload`, `redact_string`) prior to serialization.
3. Preserves historical framework version immutability (Requirement 4):
   - Reads the assessment's `framework_kb_snapshot` and each finding's `framework_mappings_snapshot`
     so historical reports retain their original framework versions even after knowledge base updates.
"""

import html
import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.audit import record_audit_event
from app.core.exceptions import ResourceNotFoundError
from app.db.base import utc_now
from app.engine.evidence import redact_string, sanitize_payload
from app.models.assessment import Assessment, ReportArtifact
from app.models.finding import Finding
from app.models.framework import FrameworkControl, SecurityFramework

REPORT_HTML_CSP_POLICY: str = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "img-src data:; "
    "font-src 'none'; "
    "script-src 'none'; "
    "object-src 'none'; "
    "connect-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

REPORT_SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": REPORT_HTML_CSP_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

SUPPORTED_REPORT_FORMATS: set[str] = {"HTML", "JSON", "PDF"}


def _esc(value: Any) -> str:
    """Consistently redact secrets/PII and HTML-escape any value for safe HTML interpolation."""
    if value is None:
        return ""
    cleaned = redact_string(str(value))
    return html.escape(cleaned, quote=True)


def _safe_href(url: Any) -> str:
    """Validate that a URL uses an allowed http(s) scheme and HTML-escape it for `<a href="...">`."""
    if not url:
        return "#"
    raw = str(url).strip()
    if any(ch in raw for ch in ("\r", "\n", "\t", " ")):
        return "#"
    if not raw.lower().startswith(("https://", "http://")):
        return "#"
    return html.escape(raw, quote=True)


def extract_finding_framework_mappings(
    finding: Finding,
    db: Session | None = None,
) -> list[dict[str, Any]]:
    """Return immutable framework mappings for `finding`, preferring its historical snapshot."""
    rem = finding.remediation_structured or {}
    snapshot = rem.get("framework_mappings_snapshot")
    if isinstance(snapshot, list) and snapshot:
        result: list[dict[str, Any]] = []
        for item in snapshot:
            if isinstance(item, dict):
                sanitized_item = sanitize_payload(item)
                if isinstance(sanitized_item, dict):
                    result.append(sanitized_item)
        if result:
            return result

    # Fallback to relational rows if no snapshot dictionary was stored on an older finding
    mappings_out: list[dict[str, Any]] = []
    for m in finding.framework_mappings or []:
        ctrl: FrameworkControl | None = m.control
        if ctrl is None and db is not None:
            ctrl = (
                db.query(FrameworkControl)
                .filter(FrameworkControl.id == m.framework_control_id)
                .first()
            )
        fw: SecurityFramework | None = ctrl.framework if ctrl is not None else None
        if fw is None and ctrl is not None and db is not None:
            fw = (
                db.query(SecurityFramework)
                .filter(SecurityFramework.id == ctrl.framework_id)
                .first()
            )
        mappings_out.append(
            {
                "framework_control_id": m.framework_control_id,
                "framework_id": fw.id if fw else (ctrl.framework_id if ctrl else ""),
                "framework_name": fw.name if fw else "",
                "framework_version": fw.version if fw else "",
                "publisher": fw.publisher if fw else "",
                "control_id": ctrl.control_id if ctrl else m.framework_control_id,
                "title": ctrl.title if ctrl else "",
                "category": ctrl.category if ctrl else "",
                "official_reference_url": ctrl.official_reference_url if ctrl else "",
                "mapping_type": m.mapping_type,
                "mapping_rationale": redact_string(m.mapping_rationale or ""),
            }
        )
    return mappings_out


def build_pdf_bytes_from_report_payload(payload: dict[str, Any]) -> bytes:
    """Construct a valid, standards-compliant PDF 1.4 document from `payload` without external OS binaries."""
    meta = payload.get("metadata", {})
    posture = payload.get("risk_and_posture_summary", {})
    findings = payload.get("findings", [])

    lines: list[str] = [
        f"AegisAI Security Assessment Report: {redact_string(str(meta.get('title', 'Assessment Report')))}",
        f"Assessment ID: {meta.get('assessment_id', '')} | Generated: {meta.get('generated_at', '')}",
        f"Target: {redact_string(str(payload.get('target_architecture', {}).get('name', '')))} "
        f"({payload.get('target_architecture', {}).get('architecture_type', '')})",
        f"Posture Grade: {posture.get('posture_grade', 'N/A')} | Overall AVSS Risk Score: {posture.get('overall_risk_score', 0.0)}/10.0",
        f"Total Findings: {posture.get('total_findings', 0)} (Confirmed: {posture.get('confirmed_findings', 0)}, Needs Review: {posture.get('unconfirmed_findings', 0)})",
        "-" * 85,
        "Executive Summary:",
        redact_string(str(payload.get("executive_summary", "")))[:110],
        "-" * 85,
        "Vulnerability Findings Summary:",
    ]

    for idx, f in enumerate(findings[:18], start=1):
        status_tag = "CONFIRMED" if f.get("is_confirmed") else "NEEDS_REVIEW"
        lines.append(
            f"{idx}. [{f.get('severity')}] {redact_string(str(f.get('test_id')))} - "
            f"{redact_string(str(f.get('title')))} (AVSS {f.get('avss_score')}/10, "
            f"Conf: {f.get('confidence')}, {status_tag})"
        )
        rem_summary = redact_string(
            str((f.get("remediation_structured") or {}).get("summary", ""))
        )
        if rem_summary:
            lines.append(f"   Remediation: {rem_summary[:95]}")

    disclaimer = redact_string(
        str(
            payload.get("non_certification_disclaimer")
            or "NON-CERTIFICATION DISCLAIMER: Point-in-time security assessment; not a formal regulatory certification."
        )
    )
    lines.append("-" * 85)
    lines.append(f"Disclaimer: {disclaimer[:105]}")

    def _pdf_escape(text: str) -> str:
        ascii_safe = text.encode("ascii", errors="replace").decode("ascii")
        return (
            ascii_safe.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )

    content_Ops = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"]
    for line in lines:
        content_Ops.append(f"({_pdf_escape(line)}) Tj T*")
    content_Ops.append("ET")
    stream_bytes = "\n".join(content_Ops).encode("ascii")

    objects: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
        + stream_bytes
        + b"\nendstream\nendobj\n",
    ]

    pdf_out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for obj in objects:
        offsets.append(len(pdf_out))
        pdf_out.extend(obj)

    xref_pos = len(pdf_out)
    pdf_out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf_out.extend(b"0000000000 65535 f \n")
    for off in offsets:
        pdf_out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    pdf_out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(pdf_out)


class ReportGenerator:
    """Builds executive and technical security assessment reports in HTML, JSON, and PDF formats."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def generate_report(
        self,
        *,
        assessment_id: str,
        organization_id: str,
        generated_by_user_id: str | None = None,
        report_format: str = "HTML",
        title: str | None = None,
        client_ip: str = "127.0.0.1",
    ) -> ReportArtifact:
        """Generate, sanitize, and persist a ReportArtifact for a tenant-scoped Assessment."""
        fmt = (report_format or "HTML").strip().upper()
        if fmt not in SUPPORTED_REPORT_FORMATS:
            fmt = "HTML"

        assessment = (
            self.db.query(Assessment)
            .filter(
                Assessment.id == assessment_id,
                Assessment.organization_id == organization_id,
            )
            .first()
        )
        if not assessment:
            raise ResourceNotFoundError("Assessment", assessment_id)

        report_title = redact_string(
            (title or f"{assessment.name} — Security Assessment Report").strip()
        )
        generated_ts = utc_now().isoformat()

        payload = self._build_structured_payload(
            assessment=assessment,
            report_title=report_title,
            report_format=fmt,
            generated_at=generated_ts,
        )
        exec_summary = str(payload.get("executive_summary") or "")
        rendered_html = self._render_secure_html(payload)

        artifact = ReportArtifact(
            organization_id=assessment.organization_id,
            assessment_id=assessment.id,
            generated_by_user_id=generated_by_user_id,
            report_format=fmt,
            title=report_title[:240],
            executive_summary=exec_summary[:4000],
            report_payload=payload,
            rendered_html=rendered_html,
        )
        self.db.add(artifact)
        self.db.commit()
        self.db.refresh(artifact)

        record_audit_event(
            self.db,
            organization_id=assessment.organization_id,
            user_id=generated_by_user_id,
            action="REPORT_GENERATED",
            resource_type="REPORT",
            resource_id=artifact.id,
            details={
                "assessment_id": assessment.id,
                "report_format": fmt,
                "posture_grade": assessment.posture_grade,
                "overall_risk_score": assessment.overall_risk_score,
                "client_ip": client_ip,
            },
        )
        return artifact

    def render_html_from_payload(self, payload: dict[str, Any]) -> str:
        """Public helper to render a self-contained, CSP-protected HTML document from a structured report payload."""
        return self._render_secure_html(payload)

    def _build_structured_payload(
        self,
        *,
        assessment: Assessment,
        report_title: str,
        report_format: str,
        generated_at: str,
    ) -> dict[str, Any]:
        """Construct the fully sanitized structured JSON report payload."""
        summary_metrics = sanitize_payload(assessment.summary_metrics or {})
        if not isinstance(summary_metrics, dict):
            summary_metrics = {}

        status_counts: dict[str, int] = summary_metrics.get("status_counts", {})
        severity_counts: dict[str, int] = summary_metrics.get("severity_counts", {})

        # Sort findings by AVSS score descending, then test_id
        sorted_findings = sorted(
            assessment.findings or [],
            key=lambda f: (-float(f.avss_score or 0.0), f.test_id),
        )
        confirmed_count = sum(1 for f in sorted_findings if f.is_confirmed)
        unconfirmed_count = sum(1 for f in sorted_findings if not f.is_confirmed)

        # Build historical framework KB snapshot (preserving immutable versions from assessment run time)
        kb_snapshot = summary_metrics.get("framework_kb_snapshot")
        if isinstance(kb_snapshot, list):
            kb_snapshot = {
                str(item["id"]): item
                for item in kb_snapshot
                if isinstance(item, dict) and item.get("id")
            }
        if not isinstance(kb_snapshot, dict) or not kb_snapshot:
            kb_snapshot = {
                fw.id: {
                    "id": fw.id,
                    "name": fw.name,
                    "version": fw.version,
                    "publisher": fw.publisher,
                    "release_date": fw.release_date,
                    "official_url": fw.official_url,
                    "description": fw.description,
                }
                for fw in self.db.query(SecurityFramework).all()
            }

        serialized_findings: list[dict[str, Any]] = []
        compliance_by_framework: dict[str, dict[str, Any]] = {}

        for fw_id, fw_info in kb_snapshot.items():
            compliance_by_framework[fw_id] = {
                "framework_id": fw_id,
                "name": fw_info.get("name", fw_id),
                "version": fw_info.get("version", ""),
                "publisher": fw_info.get("publisher", ""),
                "official_url": fw_info.get("official_url", ""),
                "direct_findings_count": 0,
                "related_findings_count": 0,
                "supporting_findings_count": 0,
                "affected_controls": [],
            }

        for f in sorted_findings:
            fw_mappings = extract_finding_framework_mappings(f, self.db)
            for m in fw_mappings:
                f_id = str(m.get("framework_id") or "")
                if f_id and f_id not in compliance_by_framework:
                    compliance_by_framework[f_id] = {
                        "framework_id": f_id,
                        "name": m.get("framework_name") or f_id,
                        "version": m.get("framework_version") or "",
                        "publisher": m.get("publisher") or "",
                        "official_url": "",
                        "direct_findings_count": 0,
                        "related_findings_count": 0,
                        "supporting_findings_count": 0,
                        "affected_controls": [],
                    }
                if f_id in compliance_by_framework:
                    rel = str(m.get("mapping_type") or "DIRECT").upper()
                    if rel == "DIRECT":
                        compliance_by_framework[f_id]["direct_findings_count"] += 1
                    elif rel == "RELATED":
                        compliance_by_framework[f_id]["related_findings_count"] += 1
                    else:
                        compliance_by_framework[f_id]["supporting_findings_count"] += 1

                    ctrl_code = str(m.get("control_id") or m.get("framework_control_id"))
                    if ctrl_code not in compliance_by_framework[f_id]["affected_controls"]:
                        compliance_by_framework[f_id]["affected_controls"].append(ctrl_code)

            ev_list = [
                {
                    "id": ev.id,
                    "probe_name": redact_string(ev.probe_name),
                    "detector_name": redact_string(ev.detector_name),
                    "http_status": ev.http_status,
                    "latency_ms": ev.latency_ms,
                    "matched_artifacts": sanitize_payload(ev.matched_artifacts),
                    "request_payload": sanitize_payload(ev.request_payload),
                    "response_payload": sanitize_payload(ev.response_payload),
                }
                for ev in (f.evidence_items or [])
            ]

            rem_clean = sanitize_payload(f.remediation_structured or {})
            if not isinstance(rem_clean, dict):
                rem_clean = {}

            serialized_findings.append(
                {
                    "id": f.id,
                    "test_id": redact_string(f.test_id),
                    "title": redact_string(f.title),
                    "module": redact_string(f.module),
                    "category": redact_string(f.category),
                    "affected_component": redact_string(f.affected_component),
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "is_confirmed": bool(f.is_confirmed),
                    "confirmation_status": "CONFIRMED" if f.is_confirmed else "UNCONFIRMED_NEEDS_REVIEW",
                    "avss_score": f.avss_score,
                    "avss_vector": redact_string(f.avss_vector),
                    "severity_rationale": redact_string(f.severity_rationale),
                    "description": redact_string(f.description),
                    "exploitability_summary": redact_string(f.exploitability_summary),
                    "remediation_structured": rem_clean,
                    "framework_mappings": fw_mappings,
                    "evidence_items": ev_list,
                }
            )

        serialized_tests = [
            {
                "id": tr.id,
                "test_id": redact_string(tr.test_id),
                "module": redact_string(tr.module),
                "test_title": redact_string(tr.test_title),
                "test_category": redact_string(tr.test_category),
                "target_component": redact_string(tr.target_component),
                "execution_status": tr.execution_status,
                "vulnerability_status": tr.vulnerability_status,
                "probes_sent": tr.probes_sent,
                "execution_duration_ms": tr.execution_duration_ms,
                "execution_log": sanitize_payload(tr.execution_log or {}),
            }
            for tr in sorted(assessment.test_results or [], key=lambda r: r.test_id)
        ]

        target_snap = sanitize_payload(assessment.target_profile_snapshot or {})
        if not isinstance(target_snap, dict):
            target_snap = {}

        target_name = str(target_snap.get("name") or "Target AI System")
        arch_type = str(target_snap.get("architecture_type") or "LLM_APP")
        grade = assessment.posture_grade or "A"

        exec_summary = redact_string(
            f"AegisAI executed {assessment.tests_completed} security test suite(s) across modules "
            f"{', '.join(assessment.selected_modules or [])} against target '{target_name}' ({arch_type}). "
            f"The target achieved Security Posture Grade '{grade}' with an overall AVSS v1.0 risk score of "
            f"{assessment.overall_risk_score:.1f}/10.0. "
            f"A total of {len(serialized_findings)} security finding(s) were surfaced "
            f"({confirmed_count} confirmed FAIL, {unconfirmed_count} flagged as NEEDS_REVIEW for analyst verification)."
        )

        prioritized_remediation_plan = [
            {
                "rank": idx,
                "finding_id": f["id"],
                "test_id": f["test_id"],
                "title": f["title"],
                "affected_component": f["affected_component"],
                "severity": f["severity"],
                "avss_score": f["avss_score"],
                "priority": f["remediation_structured"].get("priority", f["severity"]),
                "summary": f["remediation_structured"].get("summary", ""),
            }
            for idx, f in enumerate(serialized_findings, start=1)
        ]

        non_certification_disclaimer = (
            "NON-CERTIFICATION & POINT-IN-TIME ASSESSMENT DISCLAIMER: This AegisAI Security Assessment "
            "Report documents technical security evaluation outcomes observed at a specific point in time "
            "against the declared target configuration and authorized scope. It does not constitute formal "
            "regulatory certification, legal compliance attestation, or a guarantee of immunity against "
            "future or zero-day adversarial threats."
        )

        raw_payload = {
            "metadata": {
                "title": report_title,
                "report_format": report_format,
                "generated_at": generated_at,
                "assessment_id": assessment.id,
                "organization_id": assessment.organization_id,
                "assessment_name": redact_string(assessment.name),
                "selected_modules": list(assessment.selected_modules or []),
                "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
                "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
            },
            "assessment": {
                "id": assessment.id,
                "organization_id": assessment.organization_id,
                "target_profile_id": assessment.target_profile_id,
                "name": redact_string(assessment.name),
                "status": assessment.status,
                "posture_grade": grade,
                "overall_risk_score": assessment.overall_risk_score,
                "selected_modules": list(assessment.selected_modules or []),
                "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
                "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
            },
            "executive_summary": exec_summary,
            "non_certification_disclaimer": non_certification_disclaimer,
            "scope_and_attestation": sanitize_payload(assessment.scope_attestation or {}),
            "target_architecture": target_snap,
            "risk_and_posture_summary": {
                "overall_risk_score": assessment.overall_risk_score,
                "posture_grade": grade,
                "total_tests_planned": assessment.total_tests_planned,
                "tests_completed": assessment.tests_completed,
                "total_findings": len(serialized_findings),
                "confirmed_findings": confirmed_count,
                "unconfirmed_findings": unconfirmed_count,
                "status_counts": status_counts,
                "severity_counts": severity_counts,
            },
            "framework_kb_snapshot": kb_snapshot,
            "framework_compliance_matrix": list(compliance_by_framework.values()),
            "prioritized_remediation_plan": prioritized_remediation_plan,
            "test_execution_matrix": serialized_tests,
            "findings": serialized_findings,
        }
        sanitized = sanitize_payload(raw_payload)
        return sanitized if isinstance(sanitized, dict) else raw_payload

    def _render_secure_html(self, payload: dict[str, Any]) -> str:
        """Render a self-contained, CSP-protected, comprehensively HTML-escaped enterprise report."""
        meta = payload.get("metadata", {})
        posture = payload.get("risk_and_posture_summary", {})
        target = payload.get("target_architecture", {})
        scope = payload.get("scope_and_attestation", {})
        findings = payload.get("findings", [])
        tests = payload.get("test_execution_matrix", [])
        fw_matrix = payload.get("framework_compliance_matrix", [])

        # Build Test Execution Matrix rows
        test_rows_html: list[str] = []
        for tr in tests:
            test_rows_html.append(
                f"<tr>"
                f"<td><code>{_esc(tr.get('test_id'))}</code></td>"
                f"<td>{_esc(tr.get('module'))}</td>"
                f"<td>{_esc(tr.get('test_title'))}</td>"
                f"<td><code>{_esc(tr.get('target_component'))}</code></td>"
                f"<td><span class='badge status-{_esc(tr.get('execution_status'))}'>{_esc(tr.get('execution_status'))}</span></td>"
                f"<td>{_esc(tr.get('vulnerability_status'))}</td>"
                f"<td>{_esc(tr.get('probes_sent'))}</td>"
                f"<td>{_esc(tr.get('execution_duration_ms'))} ms</td>"
                f"</tr>"
            )

        # Build Framework Compliance Matrix rows
        fw_rows_html: list[str] = []
        for fw in fw_matrix:
            controls_str = ", ".join(str(c) for c in (fw.get("affected_controls") or [])) or "None"
            fw_rows_html.append(
                f"<tr>"
                f"<td><code>{_esc(fw.get('framework_id'))}</code></td>"
                f"<td><a href='{_safe_href(fw.get('official_url'))}' rel='noopener noreferrer'>{_esc(fw.get('name'))}</a></td>"
                f"<td><code>{_esc(fw.get('version'))}</code></td>"
                f"<td>{_esc(fw.get('publisher'))}</td>"
                f"<td>{_esc(fw.get('direct_findings_count', 0))}</td>"
                f"<td>{_esc(fw.get('related_findings_count', 0))}</td>"
                f"<td>{_esc(fw.get('supporting_findings_count', 0))}</td>"
                f"<td><code>{_esc(controls_str)}</code></td>"
                f"</tr>"
            )

        # Build Detailed Findings cards
        findings_html: list[str] = []
        for idx, f in enumerate(findings, start=1):
            rem = f.get("remediation_structured") or {}
            prev_items = "".join(
                f"<li>{_esc(item)}</li>" for item in (rem.get("preventive_controls") or [])
            )
            det_items = "".join(
                f"<li>{_esc(item)}</li>" for item in (rem.get("detective_controls") or [])
            )
            step_items = "".join(
                f"<li>{_esc(item)}</li>" for item in (rem.get("implementation_steps") or [])
            )
            ver_items = "".join(
                f"<li>{_esc(item)}</li>" for item in (rem.get("verification_procedures") or [])
            )

            fw_badges: list[str] = []
            for m in f.get("framework_mappings") or []:
                href = _safe_href(m.get("official_reference_url"))
                m_type = _esc(m.get("mapping_type", "DIRECT"))
                fw_ver = _esc(m.get("framework_version", ""))
                fw_id = _esc(m.get("framework_id", ""))
                ctrl_id = _esc(m.get("control_id", ""))
                ctrl_title = _esc(m.get("title", ""))
                rat = _esc(m.get("mapping_rationale", ""))
                fw_badges.append(
                    f"<div class='fw-item'>"
                    f"<span class='badge rel-{m_type}'>{m_type}</span> "
                    f"<a href='{href}' rel='noopener noreferrer'><strong>{fw_id} (v{fw_ver}) — {ctrl_id}: {ctrl_title}</strong></a>"
                    f"<div class='rationale-sub'>{rat}</div>"
                    f"</div>"
                )

            ev_blocks: list[str] = []
            for ev in f.get("evidence_items") or []:
                req_json = _esc(json.dumps(ev.get("request_payload", {}), indent=2, sort_keys=True))
                resp_json = _esc(json.dumps(ev.get("response_payload", {}), indent=2, sort_keys=True))
                artifacts_str = _esc("; ".join(str(a) for a in (ev.get("matched_artifacts") or [])))
                ev_blocks.append(
                    f"<div class='evidence-box'>"
                    f"<div><strong>Probe:</strong> <code>{_esc(ev.get('probe_name'))}</code> | "
                    f"<strong>Detector:</strong> <code>{_esc(ev.get('detector_name'))}</code> | "
                    f"<strong>HTTP Status:</strong> {_esc(ev.get('http_status'))} | "
                    f"<strong>Latency:</strong> {_esc(ev.get('latency_ms'))} ms</div>"
                    f"<div><strong>Matched Indicators:</strong> <code>{artifacts_str}</code></div>"
                    f"<div class='code-grid'>"
                    f"<div><h5>Redacted Request Payload</h5><pre><code>{req_json}</code></pre></div>"
                    f"<div><h5>Redacted Response Payload</h5><pre><code>{resp_json}</code></pre></div>"
                    f"</div>"
                    f"</div>"
                )

            conf_badge = "CONFIRMED (FAIL)" if f.get("is_confirmed") else "UNCONFIRMED (NEEDS_REVIEW)"
            findings_html.append(
                f"<section class='finding-card' id='finding-{idx}'>"
                f"<h3>{idx}. [{_esc(f.get('severity'))}] {_esc(f.get('test_id'))} — {_esc(f.get('title'))}</h3>"
                f"<div class='meta-row'>"
                f"<span class='badge sev-{_esc(f.get('severity'))}'>Severity: {_esc(f.get('severity'))}</span> "
                f"<span class='badge'>AVSS v1.0: {_esc(f.get('avss_score'))}/10.0</span> "
                f"<span class='badge'>Confidence: {_esc(f.get('confidence'))}</span> "
                f"<span class='badge'>Status: {_esc(conf_badge)}</span> "
                f"<span class='badge'>Component: <code>{_esc(f.get('affected_component'))}</code></span>"
                f"</div>"
                f"<p><strong>AVSS Vector:</strong> <code>{_esc(f.get('avss_vector'))}</code></p>"
                f"<p><strong>Severity &amp; Confidence Rationale:</strong> {_esc(f.get('severity_rationale'))}</p>"
                f"<p><strong>Technical Description:</strong> {_esc(f.get('description'))}</p>"
                f"<p><strong>Exploitability Summary:</strong> {_esc(f.get('exploitability_summary'))}</p>"
                f"<h4>Authoritative Framework Mappings (DIRECT / RELATED / SUPPORTING)</h4>"
                f"<div class='fw-list'>{''.join(fw_badges) or '<p>No framework mappings recorded.</p>'}</div>"
                f"<h4>Sanitized Technical Evidence</h4>"
                f"{''.join(ev_blocks) or '<p>No technical evidence items captured.</p>'}"
                f"<h4>8-Part Actionable Remediation Guidance (Priority: {_esc(rem.get('priority', f.get('severity')))})</h4>"
                f"<div class='remediation-box'>"
                f"<p><strong>1. Remediation Summary:</strong> {_esc(rem.get('summary'))}</p>"
                f"<p><strong>2. Architectural Root Cause:</strong> {_esc(rem.get('root_cause'))}</p>"
                f"<p><strong>3. Priority Level:</strong> <code>{_esc(rem.get('priority', f.get('severity')))}</code></p>"
                f"<div><strong>4. Preventive Controls:</strong><ul>{prev_items}</ul></div>"
                f"<div><strong>5. Detective Controls:</strong><ul>{det_items}</ul></div>"
                f"<div><strong>6. Implementation Steps:</strong><ol>{step_items}</ol></div>"
                f"<div><strong>7. Reference Secure Code Pattern:</strong><pre><code>{_esc(rem.get('secure_code_example'))}</code></pre></div>"
                f"<div><strong>8. Verification &amp; Re-Testing Procedures:</strong><ol>{ver_items}</ol></div>"
                f"</div>"
                f"</section>"
            )

        findings_section = (
            "\n".join(findings_html)
            if findings_html
            else "<p>Zero vulnerabilities or review-required findings were identified during this assessment.</p>"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{REPORT_HTML_CSP_POLICY}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(meta.get('title', 'AegisAI Security Assessment Report'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 24px; line-height: 1.5; }}
  .container {{ max-width: 1180px; margin: 0 auto; background: #ffffff; padding: 32px; border: 1px solid #e2e8f0; border-radius: 8px; }}
  h1, h2, h3, h4 {{ color: #0f172a; margin-top: 1.2em; margin-bottom: 0.5em; }}
  code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.88em; }}
  pre {{ background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.92em; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.82em; font-weight: 600; background: #e2e8f0; color: #1e293b; margin-right: 4px; }}
  .sev-CRITICAL, .status-FAIL {{ background: #fee2e2; color: #991b1b; }}
  .sev-HIGH {{ background: #ffedd5; color: #9a3412; }}
  .sev-MEDIUM, .status-NEEDS_REVIEW {{ background: #fef3c7; color: #92400e; }}
  .sev-LOW {{ background: #e0f2fe; color: #075985; }}
  .status-PASS {{ background: #dcfce7; color: #166534; }}
  .status-ERROR {{ background: #f3e8ff; color: #6b21a8; }}
  .rel-DIRECT {{ background: #dbeafe; color: #1e40af; }}
  .rel-RELATED {{ background: #fef3c7; color: #92400e; }}
  .rel-SUPPORTING {{ background: #f1f5f9; color: #334155; }}
  .finding-card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin: 20px 0; background: #ffffff; page-break-inside: avoid; }}
  .evidence-box, .remediation-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px; margin: 10px 0; }}
  .fw-item {{ margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px dashed #e2e8f0; }}
  .rationale-sub {{ font-size: 0.88em; color: #475569; margin-top: 2px; }}
  @media print {{ body {{ background: #fff; padding: 0; }} .container {{ border: none; padding: 0; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>{_esc(meta.get('title'))}</h1>
    <p>
      <strong>Assessment ID:</strong> <code>{_esc(meta.get('assessment_id'))}</code> |
      <strong>Target:</strong> {_esc(target.get('name'))} (<code>{_esc(target.get('architecture_type'))}</code> / <code>{_esc(target.get('integration_mode'))}</code>) |
      <strong>Generated At:</strong> <code>{_esc(meta.get('generated_at'))}</code>
    </p>
    <p>
      <strong>Posture Grade:</strong> <span class="badge">{_esc(posture.get('posture_grade'))}</span> |
      <strong>Overall AVSS Risk Score:</strong> <span class="badge">{_esc(posture.get('overall_risk_score'))}/10.0</span> |
      <strong>Scope Attestation SHA-256:</strong> <code>{_esc(scope.get('scope_attestation_hash', 'N/A'))}</code>
    </p>
  </header>

  <section>
    <h2>1. Executive Summary</h2>
    <p>{_esc(payload.get('executive_summary'))}</p>
  </section>

  <section>
    <h2>2. Authoritative Framework Compliance Matrix (Immutable Version Snapshot)</h2>
    <table>
      <thead>
        <tr>
          <th>Framework ID</th>
          <th>Standard</th>
          <th>Version</th>
          <th>Publisher</th>
          <th>DIRECT</th>
          <th>RELATED</th>
          <th>SUPPORTING</th>
          <th>Mapped Controls</th>
        </tr>
      </thead>
      <tbody>
        {"".join(fw_rows_html)}
      </tbody>
    </table>
  </section>

  <section>
    <h2>3. Security Test Execution Matrix</h2>
    <table>
      <thead>
        <tr>
          <th>Test ID</th>
          <th>Module</th>
          <th>Test Suite Title</th>
          <th>Target Component</th>
          <th>Execution Status</th>
          <th>Vulnerability Status</th>
          <th>Probes</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>
        {"".join(test_rows_html)}
      </tbody>
    </table>
  </section>

  <section>
    <h2>4. Detailed Vulnerability Findings, Evidence &amp; 8-Part Remediation</h2>
    {findings_section}
  </section>

  <footer>
    <hr>
    <p><small><strong>Non-Certification Disclaimer:</strong> {_esc(payload.get('non_certification_disclaimer'))}</small></p>
  </footer>
</div>
</body>
</html>"""
