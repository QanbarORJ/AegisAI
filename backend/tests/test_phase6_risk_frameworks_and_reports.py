"""Phase 6 Dedicated Verification Suite:
1. Authoritative Framework Knowledge Base Seeding & Schema Validation (6 Frameworks)
2. Evidence-Driven Conditional Framework Mappings (DIRECT, RELATED, SUPPORTING)
3. Immutable Framework Versions & Historical Assessment Retention
4. AVSS v1.0 Risk Engine & Strict Separation of Severity, Confidence, and Confirmation Status
5. Actionable 8-Part Remediation Guidance Engine
6. Enterprise HTML/JSON/PDF Report Generator, CSP Headers, XSS Escaping & Secret Sanitization
7. Strict Multi-Tenant Isolation & RBAC Enforcement across Findings, Compliance & Reports APIs
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.engine.contracts import (
    ConfidenceLevel,
    ExecutionStatus,
    NormalizedTestResult,
    SeverityLevel,
    TechnicalEvidenceItem,
    VulnerabilityStatus,
)
from app.engine.framework_mapper import (
    FrameworkMappingEngine,
    ImmutableFrameworkVersionError,
    MappingRelationshipType,
    ensure_knowledge_base_seeded,
    seed_framework_bundle,
)
from app.engine.remediation_engine import RemediationEngine
from app.engine.report_generator import (
    REPORT_HTML_CSP_POLICY,
    REPORT_SECURITY_HEADERS,
    _safe_href,
)
from app.engine.risk_engine import (
    RiskAssessmentEngine,
    compute_avss_v1,
    parse_avss_vector,
)
from app.models.framework import FrameworkControl, SecurityFramework


def test_authoritative_knowledge_base_seeding_and_immutability(
    db_session: Session,
) -> None:
    """Verify all 6 frameworks seed cleanly and enforce version immutability (Requirement 4)."""
    seeded = ensure_knowledge_base_seeded(db_session)
    expected_ids = {
        "OWASP_LLM_2026",
        "OWASP_AGENTIC_2026",
        "OWASP_AISVS_V1",
        "NIST_AI_RMF_600_1",
        "MITRE_ATLAS",
        "ISO_42001_23894",
    }
    assert expected_ids.issubset(set(seeded.keys()))

    # Verify controls count and valid official URLs
    all_controls = db_session.query(FrameworkControl).all()
    assert len(all_controls) >= 58
    for ctrl in all_controls:
        assert ctrl.official_reference_url.startswith(("https://", "http://"))
        assert len(ctrl.title) >= 3
        assert len(ctrl.description) >= 10

    # Idempotent re-seeding with identical metadata/controls must succeed without error
    ensure_knowledge_base_seeded(db_session)

    # Attempting to overwrite an existing framework version with altered metadata or controls
    # MUST raise ImmutableFrameworkVersionError (Requirement 4)
    tampered_bundle = {
        "framework": {
            "id": "OWASP_LLM_2026",
            "name": "Tampered OWASP Title",
            "version": "2026-modified",
            "publisher": "OWASP Foundation",
            "release_date": "2026-01",
            "description": "Attempted in-place overwrite of immutable framework version.",
            "official_url": "https://genai.owasp.org/llm-top-10/",
        },
        "controls": [],
    }
    with pytest.raises(ImmutableFrameworkVersionError) as exc_info:
        seed_framework_bundle(db_session, tampered_bundle, enforce_immutability=True)
    assert exc_info.value.status_code == 409

    # Confirm original OWASP_LLM_2026 record was not altered
    owasp_llm = (
        db_session.query(SecurityFramework)
        .filter(SecurityFramework.id == "OWASP_LLM_2026")
        .one()
    )
    assert owasp_llm.version == "2026"
    assert owasp_llm.name == "OWASP Top 10 for Large Language Model Applications"


def test_evidence_driven_conditional_framework_mappings(
    db_session: Session,
) -> None:
    """Verify DIRECT, RELATED, and SUPPORTING relationships and conditional evidence triggers (Requirement 1)."""
    ensure_knowledge_base_seeded(db_session)
    mapper = FrameworkMappingEngine(db_session)

    # 1. LLM-IOH-001 with Markdown Image Beacon + SQL Sink Payload conditional evidence
    output_with_beacon_and_sql = NormalizedTestResult(
        test_id="LLM-IOH-001",
        test_title="Improper Output Handling & Unsanitized Rendering",
        assessment_id="asmt-test-001",
        target_component="LLM_OUTPUT_SINK",
        test_category="Improper Output Handling",
        module="LLM",
        execution_status=ExecutionStatus.FAIL,
        vulnerability_status=VulnerabilityStatus.VULNERABLE,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        risk_score=8.2,
        avss_vector="AVSS:1.0/I:8.5/E:8.0/B:8.0/X:8.0/C:1.00/CONF:HIGH",
        risk_rationale="XSS, Markdown beacon, and SQL sink reflected.",
        description="Unsanitized output rendering.",
        exploitability_summary="Reflected XSS and SQL payload.",
        technical_evidence=[
            TechnicalEvidenceItem(
                probe_index=0,
                probe_name="Markdown Exfiltration & SQL Sink Probe",
                request_payload_redacted={"prompt": "Render image beacon and SQL query"},
                response_body_redacted={
                    "output": "![exfil](https://canary.aegis.invalid/collect) SELECT * FROM users"
                },
                http_status_code=200,
                latency_ms=25.0,
                detector_type="SINK_AST_DETECTOR",
                matched_indicators=[
                    "Raw Script Tag",
                    "Markdown Image Beacon",
                    "SQL Sink Payload",
                ],
                target_component="LLM_OUTPUT_SINK",
            )
        ],
    )

    decisions = mapper.resolve_mappings_for_result(
        output_with_beacon_and_sql, architecture_type="HYBRID"
    )
    rel_types = {d.mapping_type.value for d in decisions}
    assert MappingRelationshipType.DIRECT.value in rel_types
    assert MappingRelationshipType.RELATED.value in rel_types
    assert MappingRelationshipType.SUPPORTING.value in rel_types

    by_key = {d.framework_control_id: d for d in decisions}
    # Primary DIRECT mapping for LLM-IOH-001
    assert "OWASP_LLM_2026:LLM10" in by_key
    assert by_key["OWASP_LLM_2026:LLM10"].mapping_type == MappingRelationshipType.DIRECT
    assert "OWASP_AISVS_V1:C3" in by_key
    assert by_key["OWASP_AISVS_V1:C3"].mapping_type == MappingRelationshipType.DIRECT
    # Conditional indicator mapping: Markdown Image Beacon -> MITRE ATLAS AML.T0048 (RELATED) & LLM02 (RELATED)
    assert "MITRE_ATLAS:AML.T0048" in by_key
    assert by_key["MITRE_ATLAS:AML.T0048"].mapping_type == MappingRelationshipType.RELATED
    assert "Markdown Image Beacon" in by_key["MITRE_ATLAS:AML.T0048"].mapping_rationale
    assert "OWASP_LLM_2026:LLM02" in by_key
    # Conditional indicator mapping: SQL Sink Payload -> OWASP_AGENTIC_2026:ASI06 (RELATED)
    assert "OWASP_AGENTIC_2026:ASI06" in by_key
    assert by_key["OWASP_AGENTIC_2026:ASI06"].mapping_type == MappingRelationshipType.RELATED

    # 2. Conditional Applicability without relying on test_id (novel custom plugin ID)
    novel_agent_finding = NormalizedTestResult(
        test_id="CUSTOM-AGENT-ZERO-DAY-999",
        test_title="Custom Autonomous Tool Privilege Escalation",
        assessment_id="asmt-test-001",
        target_component="AGENT_TOOL_ROUTER",
        test_category="Tool Misuse & Privilege Escalation",
        module="AGENT",
        execution_status=ExecutionStatus.FAIL,
        vulnerability_status=VulnerabilityStatus.VULNERABLE,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        risk_score=9.4,
        avss_vector="AVSS:1.0/I:9.5/E:9.0/B:9.5/X:9.0/C:1.00/CONF:HIGH",
        risk_rationale="Custom agent tool invoked privileged shell action.",
        description="Unbounded agent tool invocation.",
        exploitability_summary="Direct tool abuse.",
        technical_evidence=[
            TechnicalEvidenceItem(
                probe_index=0,
                probe_name="Custom Tool Escalation Probe",
                request_payload_redacted={"prompt": "Invoke admin_shell"},
                response_body_redacted={"tool_calls": [{"name": "admin_shell"}]},
                http_status_code=200,
                latency_ms=42.0,
                detector_type="TOOL_CALL_VALIDATOR",
                matched_indicators=["Unauthorized Tool Call: admin_shell"],
                target_component="AGENT_TOOL_ROUTER",
            )
        ],
    )
    novel_decisions = mapper.resolve_mappings_for_result(
        novel_agent_finding, architecture_type="AI_AGENT"
    )
    novel_keys = {d.framework_control_id: d for d in novel_decisions}
    # Even though test_id="CUSTOM-AGENT-ZERO-DAY-999" is not a built-in test_id,
    # conditional component + category rules map it to ASI02, LLM03, C10, ASI03, MG-2.2, A.6.2.3
    assert "OWASP_AGENTIC_2026:ASI02" in novel_keys
    assert novel_keys["OWASP_AGENTIC_2026:ASI02"].mapping_type == MappingRelationshipType.DIRECT
    assert "OWASP_LLM_2026:LLM03" in novel_keys
    assert "OWASP_AISVS_V1:C10" in novel_keys
    assert "NIST_AI_RMF_600_1:MG-2.2" in novel_keys
    assert novel_keys["NIST_AI_RMF_600_1:MG-2.2"].mapping_type == MappingRelationshipType.SUPPORTING


def test_avss_severity_confidence_and_confirmation_strict_separation() -> None:
    """Verify low confidence NEVER reduces underlying AVSS severity or score (Requirement 3)."""
    risk_engine = RiskAssessmentEngine()

    score_high, sev_high, vec_high = compute_avss_v1(
        impact=9.0,
        exploitability=8.5,
        blast_radius=8.5,
        exposure=8.0,
        compensating_multiplier=1.0,
        confidence=ConfidenceLevel.HIGH,
    )
    score_low, sev_low, vec_low = compute_avss_v1(
        impact=9.0,
        exploitability=8.5,
        blast_radius=8.5,
        exposure=8.0,
        compensating_multiplier=1.0,
        confidence=ConfidenceLevel.LOW,
    )

    # Low confidence must never reduce AVSS score or severity
    assert score_high == score_low
    assert sev_high == sev_low
    assert vec_high.endswith("/CONF:HIGH")
    assert vec_low.endswith("/CONF:LOW")

    confirmed_norm = NormalizedTestResult(
        test_id="LLM-PI-001",
        test_title="Direct Prompt Injection",
        assessment_id="asmt-test-001",
        target_component="LLM_SYSTEM_PROMPT_BOUNDARY",
        test_category="Direct Prompt Injection",
        module="LLM",
        execution_status=ExecutionStatus.FAIL,
        vulnerability_status=VulnerabilityStatus.VULNERABLE,
        severity=sev_high,
        confidence=ConfidenceLevel.HIGH,
        risk_score=score_high,
        avss_vector=vec_high,
        risk_rationale="Confirmed direct injection.",
        description="Confirmed direct injection.",
        exploitability_summary="Deterministic exploitability.",
    )
    suspected_norm = NormalizedTestResult(
        test_id="LLM-PI-001",
        test_title="Direct Prompt Injection",
        assessment_id="asmt-test-001",
        target_component="LLM_SYSTEM_PROMPT_BOUNDARY",
        test_category="Direct Prompt Injection",
        module="LLM",
        execution_status=ExecutionStatus.NEEDS_REVIEW,
        vulnerability_status=VulnerabilityStatus.POTENTIALLY_VULNERABLE,
        severity=sev_low,
        confidence=ConfidenceLevel.LOW,
        risk_score=score_low,
        avss_vector=vec_low,
        risk_rationale="Ambiguous heuristic compliance signal.",
        description="Suspected direct injection.",
        exploitability_summary="Heuristic exploitability.",
    )

    eval_confirmed = risk_engine.evaluate_finding_risk(confirmed_norm)
    eval_suspected = risk_engine.evaluate_finding_risk(suspected_norm)

    # 1. Confirmation status and confidence are strictly separated
    assert eval_confirmed.is_confirmed is True
    assert eval_confirmed.confirmation_status == "CONFIRMED"
    assert eval_confirmed.confidence == ConfidenceLevel.HIGH
    assert eval_suspected.is_confirmed is False
    assert eval_suspected.confirmation_status == "UNCONFIRMED_NEEDS_REVIEW"
    assert eval_suspected.confidence == ConfidenceLevel.LOW

    # 2. Underlying AVSS score and severity MUST be identical (Requirement 3)
    assert eval_confirmed.avss_score == eval_suspected.avss_score
    assert eval_confirmed.severity == eval_suspected.severity
    assert eval_suspected.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)

    # Verify AVSS vector string round-trip parsing
    parsed = parse_avss_vector(eval_confirmed.avss_vector)
    assert parsed is not None
    recomputed_score, recomputed_sev, _ = compute_avss_v1(
        impact=parsed["impact"],
        exploitability=parsed["exploitability"],
        blast_radius=parsed["blast_radius"],
        exposure=parsed["exposure"],
        compensating_multiplier=parsed["compensating_multiplier"],
        confidence=ConfidenceLevel(parsed["confidence"]),
    )
    assert recomputed_score == eval_confirmed.avss_score
    assert recomputed_sev == eval_confirmed.severity


def test_eight_part_remediation_engine_specificity() -> None:
    """Verify RemediationEngine generates all 8 required actionable sections (Requirement 2)."""
    rem_engine = RemediationEngine()
    sample_output = NormalizedTestResult(
        test_id="AGT-PERM-001",
        test_title="Human-in-the-Loop Gate & Permission Scope Audit",
        assessment_id="asmt-test-001",
        target_component="AGENT_HITL_APPROVAL_GATE",
        test_category="Human-in-the-Loop & Permission Scope",
        module="AGENT",
        execution_status=ExecutionStatus.FAIL,
        vulnerability_status=VulnerabilityStatus.VULNERABLE,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        risk_score=8.4,
        avss_vector="AVSS:1.0/I:8.5/E:8.0/B:8.5/X:8.0/C:1.00/CONF:HIGH",
        risk_rationale="Missing HITL gates and excessive agent iteration ceiling.",
        description="Configuration and runtime audit identified missing controls.",
        exploitability_summary="Direct configuration and HITL bypass exposure.",
        technical_evidence=[
            TechnicalEvidenceItem(
                probe_index=0,
                probe_name="CFG-AGT-002 & CFG-AGT-003 Static Audit",
                request_payload_redacted={"check": "agent_manifest_audit"},
                response_body_redacted={"finding": "max_iterations=50 and additionalProperties=true"},
                http_status_code=None,
                latency_ms=1.0,
                detector_type="CONFIG_RULE",
                matched_indicators=["CFG-AGT-002", "CFG-AGT-003"],
                target_component="AGENT_HITL_APPROVAL_GATE",
            )
        ],
    )

    payload = rem_engine.build_remediation(
        sample_output, effective_severity=SeverityLevel.HIGH
    )

    required_8_keys = {
        "summary",
        "root_cause",
        "priority",
        "preventive_controls",
        "detective_controls",
        "implementation_steps",
        "secure_code_example",
        "verification_procedures",
    }
    assert required_8_keys.issubset(set(payload.keys()))
    assert len(payload["preventive_controls"]) >= 3
    assert len(payload["detective_controls"]) >= 2
    assert len(payload["implementation_steps"]) >= 3
    assert len(payload["verification_procedures"]) >= 3
    assert len(payload["secure_code_example"]) >= 40
    # Verify rule-specific tailoring was injected for CFG-AGT-002 and CFG-AGT-003
    combined_steps = " ".join(payload["implementation_steps"])
    assert "CFG-AGT-002" in combined_steps
    assert "CFG-AGT-003" in combined_steps


def test_phase6_end_to_end_apis_reports_csp_immutability_and_tenancy(
    client: TestClient,
    db_session: Session,
    multi_tenant_seed: dict[str, object],
) -> None:
    """Verify Phase 6 APIs, HTML/JSON/PDF reports, CSP/XSS hardening, historical KB immutability, and tenant isolation."""
    tokens = multi_tenant_seed["tokens"]  # type: ignore[index]
    alpha_admin_headers = {"Authorization": f"Bearer {tokens['alpha_admin']}"}
    alpha_viewer_headers = {"Authorization": f"Bearer {tokens['alpha_viewer']}"}
    beta_admin_headers = {"Authorization": f"Bearer {tokens['beta_admin']}"}

    # 1. Verify /api/v1/frameworks endpoints
    fw_list_resp = client.get("/api/v1/frameworks", headers=alpha_admin_headers)
    assert fw_list_resp.status_code == 200
    fw_list = fw_list_resp.json()
    assert len(fw_list) == 6
    fw_ids = {item["id"] for item in fw_list}
    assert fw_ids == {
        "OWASP_LLM_2026",
        "OWASP_AGENTIC_2026",
        "OWASP_AISVS_V1",
        "NIST_AI_RMF_600_1",
        "MITRE_ATLAS",
        "ISO_42001_23894",
    }

    owasp_detail_resp = client.get(
        "/api/v1/frameworks/OWASP_LLM_2026", headers=alpha_admin_headers
    )
    assert owasp_detail_resp.status_code == 200
    owasp_detail = owasp_detail_resp.json()
    assert owasp_detail["version"] == "2026"
    assert owasp_detail["control_count"] == 10
    assert len(owasp_detail["controls"]) == 10

    missing_fw_resp = client.get(
        "/api/v1/frameworks/NON_EXISTENT_FW", headers=alpha_admin_headers
    )
    assert missing_fw_resp.status_code == 404

    # 2. Create a TargetProfile and run a full LLM+RAG+AGENT assessment for Org Alpha
    create_target_resp = client.post(
        "/api/v1/targets",
        headers=alpha_admin_headers,
        json={
            "name": "Alpha Enterprise RAG & Agent Copilot <script>alert(1)</script>",
            "architecture_type": "HYBRID",
            "integration_mode": "SIMULATOR",
            "endpoint_url": "https://vulnerable-rag-agent.alpha.example.com/v1/chat",
            "allowed_hosts": ["vulnerable-rag-agent.alpha.example.com"],
            "auth_type": "BEARER",
            "credentials": {"token": "sk-proj-SUPERSECRETKEY1234567890ABCDEF"},
            "architecture_manifest": {
                "simulator_preset": "vulnerable",
                "guardrails_enabled": False,
            },
            "rag_harness_config": {
                "enabled": True,
                "vector_store": "pgvector",
            },
            "agent_harness_config": {
                "enabled": True,
                "tools": ["read_docs", "execute_sql", "send_webhook"],
            },
            "rate_limit_rps": 5.0,
            "timeout_seconds": 15,
        },
    )
    assert create_target_resp.status_code == 201
    target_id = create_target_resp.json()["id"]

    create_asmt_resp = client.post(
        "/api/v1/assessments",
        headers=alpha_admin_headers,
        json={
            "name": "Phase 6 Full Compliance & Report Verification <svg onload=alert(9)>",
            "target_profile_id": target_id,
            "selected_modules": ["LLM", "RAG", "AGENT"],
            "scope_attestation": {
                "authorized": True,
                "authorizer_name": "Jane Doe, CISO",
                "authorizer_title": "Chief Information Security Officer",
                "agent_sandbox_confirmed": True,
                "notes": "Authorized Phase 6 test with secret sk-proj-ABCDEFGHIJKLMNOPQRST1234567890",
            },
        },
    )
    assert create_asmt_resp.status_code == 201
    assessment_id = create_asmt_resp.json()["id"]

    run_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/run",
        headers=alpha_admin_headers,
    )
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["status"] == "COMPLETED"
    assert run_data["posture_grade"] in ("A", "B", "C", "D", "F")
    assert "framework_kb_snapshot" in run_data["summary_metrics"]

    # 3. Verify /api/v1/findings endpoints & 8-part remediation + framework mappings
    findings_resp = client.get(
        f"/api/v1/findings?assessment_id={assessment_id}",
        headers=alpha_admin_headers,
    )
    assert findings_resp.status_code == 200
    findings_list = findings_resp.json()
    assert len(findings_list) >= 8

    sample_finding = findings_list[0]
    assert len(sample_finding["framework_mappings"]) >= 3
    mapping_types_seen = {
        m["mapping_type"] for m in sample_finding["framework_mappings"]
    }
    assert mapping_types_seen.issubset({"DIRECT", "RELATED", "SUPPORTING"})
    assert "DIRECT" in mapping_types_seen

    # Check 8-part remediation on persisted finding
    rem = sample_finding["remediation_structured"]
    for key in (
        "summary",
        "root_cause",
        "priority",
        "preventive_controls",
        "detective_controls",
        "implementation_steps",
        "secure_code_example",
        "verification_procedures",
    ):
        assert key in rem

    # Single finding detail endpoint
    single_finding_resp = client.get(
        f"/api/v1/findings/{sample_finding['id']}",
        headers=alpha_admin_headers,
    )
    assert single_finding_resp.status_code == 200
    assert single_finding_resp.json()["id"] == sample_finding["id"]

    # 4. Verify /api/v1/frameworks/compliance/summary
    compliance_resp = client.get(
        f"/api/v1/frameworks/compliance/summary?assessment_id={assessment_id}",
        headers=alpha_admin_headers,
    )
    assert compliance_resp.status_code == 200
    compliance_data = compliance_resp.json()
    assert compliance_data["organization_id"] == multi_tenant_seed["org_alpha"].id  # type: ignore[attr-defined]
    assert compliance_data["assessment_id"] == assessment_id
    assert compliance_data["total_findings_evaluated"] == len(findings_list)
    assert len(compliance_data["frameworks"]) == 6
    owasp_comp = next(
        f for f in compliance_data["frameworks"] if f["framework_id"] == "OWASP_LLM_2026"
    )
    assert owasp_comp["direct_findings_count"] >= 1
    assert owasp_comp["affected_controls_count"] >= 1

    # 5. Historical Framework Version Retention after KB Update (Requirement 4)
    # Add a new framework version OWASP_LLM_2027 to the KB after the assessment has completed
    new_2027_bundle = {
        "framework": {
            "id": "OWASP_LLM_2027",
            "name": "OWASP Top 10 for Large Language Model Applications (2027 Edition)",
            "version": "2027.1",
            "publisher": "OWASP Foundation",
            "release_date": "2027-01",
            "description": "Next-generation 2027 OWASP LLM security standard.",
            "official_url": "https://genai.owasp.org/llm-top-10/",
        },
        "controls": [
            {
                "id": "OWASP_LLM_2027:LLM01",
                "control_id": "LLM01:2027",
                "title": "2027 Prompt Injection",
                "category": "Input Manipulation",
                "description": "2027 edition prompt injection control.",
                "official_reference_url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
                "applicable_architectures": ["LLM_APP", "RAG_PIPELINE", "AI_AGENT", "HYBRID"],
            }
        ],
    }
    seed_framework_bundle(db_session, new_2027_bundle, enforce_immutability=True)

    # Verify global KB now has 7 frameworks (including OWASP_LLM_2027),
    # while historical assessment compliance summary & findings still retain exact 2026 versions!
    all_fws_after = client.get("/api/v1/frameworks", headers=alpha_admin_headers).json()
    assert len(all_fws_after) == 7

    historical_comp = client.get(
        f"/api/v1/frameworks/compliance/summary?assessment_id={assessment_id}",
        headers=alpha_admin_headers,
    ).json()
    historical_fw_versions = {
        f["framework_id"]: f["version"] for f in historical_comp["frameworks"]
    }
    assert historical_fw_versions["OWASP_LLM_2026"] == "2026"
    assert "OWASP_LLM_2027" not in historical_fw_versions

    # 6. Generate and Download Reports (HTML, JSON, PDF) & Verify Security (Requirement 5)
    # Viewer cannot generate a report (RBAC check)
    viewer_gen_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        headers=alpha_viewer_headers,
        json={"report_format": "HTML", "title": "Unauthorized Viewer Report"},
    )
    assert viewer_gen_resp.status_code == 403

    # Admin/Engineer generates HTML report
    gen_html_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        headers=alpha_admin_headers,
        json={
            "report_format": "HTML",
            "title": "Executive Assessment Report <script>evil()</script> sk-proj-SECRET99999999999999999999",
        },
    )
    assert gen_html_resp.status_code == 201
    report_data = gen_html_resp.json()
    report_id = report_data["id"]

    # Verify HTML escaping & secret sanitization inside rendered_html
    rendered_html = report_data["rendered_html"]
    assert "<script>evil()</script>" not in rendered_html
    assert "<script>alert(1)</script>" not in rendered_html
    assert "<svg onload=alert(9)>" not in rendered_html
    assert "&lt;script&gt;evil()&lt;/script&gt;" in rendered_html
    assert "sk-proj-SECRET99999999999999999999" not in rendered_html
    assert "sk-proj-ABCDEFGHIJKLMNOPQRST1234567890" not in rendered_html
    assert "[REDACTED_API_KEY]" in rendered_html
    assert REPORT_HTML_CSP_POLICY in rendered_html

    # Verify _safe_href blocks javascript: and data: URI schemes
    assert _safe_href("javascript:alert(1)") == "#"
    assert _safe_href("data:text/html,<script>alert(1)</script>") == "#"
    assert _safe_href("https://genai.owasp.org/llm-top-10/") == "https://genai.owasp.org/llm-top-10/"

    # Download HTML report and verify CSP & security response headers
    dl_html_resp = client.get(
        f"/api/v1/reports/{report_id}/download?format=HTML",
        headers=alpha_viewer_headers,
    )
    assert dl_html_resp.status_code == 200
    assert dl_html_resp.headers["content-type"].startswith("text/html")
    for hdr_key, hdr_val in REPORT_SECURITY_HEADERS.items():
        assert dl_html_resp.headers.get(hdr_key) == hdr_val
    assert "script-src 'none'" in dl_html_resp.headers["Content-Security-Policy"]

    # Download JSON report
    dl_json_resp = client.get(
        f"/api/v1/reports/{report_id}/download?format=JSON",
        headers=alpha_viewer_headers,
    )
    assert dl_json_resp.status_code == 200
    assert dl_json_resp.headers["content-type"].startswith("application/json")
    json_payload = dl_json_resp.json()
    assert json_payload["assessment"]["id"] == assessment_id
    assert len(json_payload["findings"]) == len(findings_list)
    assert "sk-proj-SECRET99999999999999999999" not in dl_json_resp.text

    # Download PDF report
    dl_pdf_resp = client.get(
        f"/api/v1/reports/{report_id}/download?format=PDF",
        headers=alpha_viewer_headers,
    )
    assert dl_pdf_resp.status_code == 200
    assert dl_pdf_resp.headers["content-type"] == "application/pdf"
    assert dl_pdf_resp.content.startswith(b"%PDF-1.4")
    assert dl_pdf_resp.content.strip().endswith(b"%%EOF")
    assert b"sk-proj-SECRET99999999999999999999" not in dl_pdf_resp.content

    # 7. Strict Multi-Tenant Isolation Verification (Requirement 6)
    # Organization Beta must receive 404 or empty lists when probing Organization Alpha's resources
    beta_findings_list = client.get(
        "/api/v1/findings", headers=beta_admin_headers
    ).json()
    assert beta_findings_list == []

    beta_findings_by_alpha_asmt = client.get(
        f"/api/v1/findings?assessment_id={assessment_id}",
        headers=beta_admin_headers,
    )
    assert beta_findings_by_alpha_asmt.status_code == 404

    beta_single_finding = client.get(
        f"/api/v1/findings/{sample_finding['id']}",
        headers=beta_admin_headers,
    )
    assert beta_single_finding.status_code == 404

    beta_compliance_alpha_asmt = client.get(
        f"/api/v1/frameworks/compliance/summary?assessment_id={assessment_id}",
        headers=beta_admin_headers,
    )
    assert beta_compliance_alpha_asmt.status_code == 404

    beta_gen_report = client.post(
        f"/api/v1/assessments/{assessment_id}/reports",
        headers=beta_admin_headers,
        json={"report_format": "HTML"},
    )
    assert beta_gen_report.status_code == 404

    beta_list_reports = client.get(
        "/api/v1/reports", headers=beta_admin_headers
    ).json()
    assert beta_list_reports == []

    beta_get_report = client.get(
        f"/api/v1/reports/{report_id}", headers=beta_admin_headers
    )
    assert beta_get_report.status_code == 404

    beta_dl_report = client.get(
        f"/api/v1/reports/{report_id}/download", headers=beta_admin_headers
    )
    assert beta_dl_report.status_code == 404
