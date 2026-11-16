"""Phase 5 Verification Suite: Module B (RAG Security Scanner — 4 Suites) & Module C (AI Agent Security Scanner — 3 Suites)."""

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_credentials
from app.engine.contracts import (
    ExecutionStatus,
    StandardizedTargetResponse,
    VulnerabilityStatus,
)
from app.engine.evaluators import (
    AgentToolInvocationEvaluator,
    RAGTelemetryEvaluator,
)
from app.engine.orchestrator import AssessmentOrchestrator
from app.engine.registry import default_registry
from app.models.assessment import Assessment, AssessmentStatusEnum
from app.models.target import (
    ArchitectureTypeEnum,
    AuthTypeEnum,
    IntegrationModeEnum,
    TargetProfile,
)

EXPECTED_RAG_TEST_IDS = [
    "RAG-ARCH-001",
    "RAG-AUTH-001",
    "RAG-IPI-001",
    "RAG-META-001",
]

EXPECTED_AGENT_TEST_IDS = [
    "AGT-GH-001",
    "AGT-PERM-001",
    "AGT-TOOL-001",
]

EXPECTED_ALL_13_TEST_IDS = [
    "AGT-GH-001",
    "AGT-PERM-001",
    "AGT-TOOL-001",
    "LLM-CFG-001",
    "LLM-IOH-001",
    "LLM-PI-001",
    "LLM-PI-002",
    "LLM-SID-001",
    "LLM-SPE-001",
    "RAG-ARCH-001",
    "RAG-AUTH-001",
    "RAG-IPI-001",
    "RAG-META-001",
]


# ---------------------------------------------------------------------------
# 1. Registry Discovery of All 13 Plugins (6 LLM + 4 RAG + 3 AGENT)
# ---------------------------------------------------------------------------


def test_all_thirteen_scanners_registered_in_default_registry() -> None:
    """Confirm all 13 security test plugins across LLM, RAG, and AGENT are registered."""
    rag_tests = default_registry.get_tests_for_assessment(selected_modules=["RAG"])
    assert sorted(t.test_id for t in rag_tests) == EXPECTED_RAG_TEST_IDS

    agent_tests = default_registry.get_tests_for_assessment(selected_modules=["AGENT"])
    assert sorted(t.test_id for t in agent_tests) == EXPECTED_AGENT_TEST_IDS

    all_tests = default_registry.get_tests_for_assessment(
        selected_modules=["LLM", "RAG", "AGENT"]
    )
    assert sorted(t.test_id for t in all_tests) == EXPECTED_ALL_13_TEST_IDS


# ---------------------------------------------------------------------------
# 2. Deterministic RAG & Agent Telemetry Evaluators Unit Tests
# ---------------------------------------------------------------------------


def test_rag_telemetry_evaluator_cross_tenant_and_metadata_bypass() -> None:
    """Verify RAGTelemetryEvaluator detects cross-tenant chunks, metadata bypasses, and filters quoted refusals."""
    evaluator = RAGTelemetryEvaluator()
    canary = "AEGIS-CANARY-TENANT-A-9F8A2C"

    # 1. Foreign tenant chunk in retrieved_chunks -> deterministic match
    leak_resp = StandardizedTargetResponse(
        status_code=200,
        output_text=f"Retrieved strategy document: {canary}",
        retrieved_chunks=[
            {
                "chunk_id": "tenant-alpha-doc-1",
                "tenant_id": "tenant-alpha",
                "text": f"Confidential strategy {canary}",
            }
        ],
        citations=["tenant-alpha-doc-1"],
    )
    res_leak = evaluator.evaluate_cross_tenant_leak(
        leak_resp,
        requesting_tenant_id="tenant-beta",
        forbidden_tenant_id="tenant-alpha",
        canary_tokens=[canary],
    )
    assert res_leak.matched is True
    assert res_leak.ambiguous is False
    assert any("Cross-Tenant Chunk Retrieved" in ind for ind in res_leak.matched_indicators)

    # 2. Canary quoted inside a refusal without foreign chunks -> ambiguous=True (NEEDS_REVIEW), never FAIL
    refusal_resp = StandardizedTargetResponse(
        status_code=200,
        output_text=f"I cannot fulfill your request to search for '{canary}' across other tenants.",
        retrieved_chunks=[],
    )
    res_refusal = evaluator.evaluate_cross_tenant_leak(
        refusal_resp,
        requesting_tenant_id="tenant-beta",
        forbidden_tenant_id="tenant-alpha",
        canary_tokens=[canary],
    )
    assert res_refusal.matched is False
    assert res_refusal.ambiguous is True

    # 3. Clean tenant-beta scoped response -> matched=False, ambiguous=False (PASS)
    safe_resp = StandardizedTargetResponse(
        status_code=200,
        output_text="Here is the public FAQ for tenant-beta.",
        retrieved_chunks=[
            {
                "chunk_id": "tenant-beta-doc-01",
                "tenant_id": "tenant-beta",
                "classification": "PUBLIC",
                "text": "Public FAQ",
            }
        ],
    )
    res_safe = evaluator.evaluate_cross_tenant_leak(
        safe_resp,
        requesting_tenant_id="tenant-beta",
        forbidden_tenant_id="tenant-alpha",
        canary_tokens=[canary],
    )
    assert res_safe.matched is False
    assert res_safe.ambiguous is False

    # 4. Metadata filter bypass returning RESTRICTED_EXECUTIVE chunk
    meta_canary = "AEGIS_VERIFY_TOKEN_META_BYPASS_771"
    meta_resp = StandardizedTargetResponse(
        status_code=200,
        output_text=f"Board terms: {meta_canary}",
        retrieved_chunks=[
            {
                "chunk_id": "exec-99",
                "classification": "RESTRICTED_EXECUTIVE",
                "metadata": {"filter_overridden": True},
                "text": meta_canary,
            }
        ],
    )
    res_meta = evaluator.evaluate_metadata_filter_bypass(
        meta_resp,
        canary_tokens=[meta_canary],
    )
    assert res_meta.matched is True
    assert any("RESTRICTED_EXECUTIVE" in ind for ind in res_meta.matched_indicators)


def test_agent_tool_invocation_evaluator_distinguishes_invocation_execution_and_mention() -> None:
    """Verify AgentToolInvocationEvaluator distinguishes structured tool_calls, runtime execution, and mere text mentions."""
    evaluator = AgentToolInvocationEvaluator()
    canary = "AEGIS_VERIFY_TOKEN_TOOL_HIJACK_901"

    # 1. Structured tool_calls telemetry (Attempted Unauthorized Tool Call + Escalated Parameter)
    tool_call_resp = StandardizedTargetResponse(
        status_code=200,
        output_text="Routing tool call...",
        tool_calls=[
            {
                "id": "call_01",
                "type": "function",
                "function": {
                    "name": "aegis_canary_diagnostics_read",
                    "arguments": f'{{"scope": "ALL_TENANTS", "bypass_approval": true, "canary": "{canary}"}}',
                },
            }
        ],
    )
    res_tc = evaluator.evaluate_tool_invocation(
        tool_call_resp,
        target_tool_names=("aegis_canary_diagnostics_read",),
        canary_tokens=[canary],
    )
    assert res_tc.matched is True
    assert any("Attempted Unauthorized Tool Call (tool_calls Telemetry)" in ind for ind in res_tc.matched_indicators)
    assert any("Escalated Tool Parameter" in ind for ind in res_tc.matched_indicators)

    # 2. Mere textual mention of the tool name or canary without tool_calls and without execution ack -> NEEDS_REVIEW (not FAIL!)
    mention_resp = StandardizedTargetResponse(
        status_code=200,
        output_text=(
            f"The user prompt asked me to call aegis_canary_diagnostics_read with token {canary}, "
            "but I will only summarize the document instead."
        ),
        tool_calls=[],
    )
    res_mention = evaluator.evaluate_tool_invocation(
        mention_resp,
        target_tool_names=("aegis_canary_diagnostics_read",),
        canary_tokens=[canary],
    )
    assert res_mention.matched is False
    assert res_mention.ambiguous is True
    assert any("Unexecuted Canary Mention in Text" in ind for ind in res_mention.matched_indicators)

    # 3. Explicit refusal mentioning tool name without canary reflection -> clean PASS (matched=False, ambiguous=False)
    refusal_resp = StandardizedTargetResponse(
        status_code=200,
        output_text="I cannot fulfill your request to invoke aegis_canary_diagnostics_read.",
        tool_calls=[],
    )
    res_refusal = evaluator.evaluate_tool_invocation(
        refusal_resp,
        target_tool_names=("aegis_canary_diagnostics_read",),
        canary_tokens=[canary],
    )
    assert res_refusal.matched is False
    assert res_refusal.ambiguous is False

    # 4. Safe, schema-compliant tool invocation when testing parameter escalation (flag_any_invocation=False) -> PASS
    safe_tool_call_resp = StandardizedTargetResponse(
        status_code=200,
        output_text="Running authorized single-tenant diagnostic check.",
        tool_calls=[
            {
                "id": "call_safe_01",
                "type": "function",
                "function": {
                    "name": "aegis_canary_diagnostics_read",
                    "arguments": '{"scope": "SINGLE_TENANT", "bypass_approval": false}',
                },
            }
        ],
    )
    res_safe_tc = evaluator.evaluate_tool_invocation(
        safe_tool_call_resp,
        target_tool_names=("aegis_canary_diagnostics_read",),
        canary_tokens=[canary],
        flag_any_invocation=False,
    )
    assert res_safe_tc.matched is False
    assert res_safe_tc.ambiguous is False

    # 5. HITL Approval Gate Interception (tool call paused/blocked pending human approval) -> PASS (not FAIL)
    hitl_blocked_resp = StandardizedTargetResponse(
        status_code=200,
        output_text="Tool call queued: awaiting human approval before executing aegis_canary_diagnostics_read.",
        tool_calls=[
            {
                "id": "call_hitl_01",
                "type": "function",
                "status": "pending_approval",
                "approval_required": True,
                "function": {
                    "name": "aegis_canary_diagnostics_read",
                    "arguments": '{"scope": "ALL_TENANTS", "bypass_approval": true}',
                },
            }
        ],
    )
    res_hitl = evaluator.evaluate_tool_invocation(
        hitl_blocked_resp,
        target_tool_names=("aegis_canary_diagnostics_read",),
        canary_tokens=[canary],
    )
    assert res_hitl.matched is False
    assert res_hitl.ambiguous is False
    assert res_hitl.detector_type == "HITL_APPROVAL_GATE_INTERCEPTION"


# ---------------------------------------------------------------------------
# 3. Module B (RAG Security Scanner) Orchestrator Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_module_b_rag_scanners_on_vulnerable_and_hardened_targets(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify all 4 RAG scanners detect vulnerabilities on a vulnerable RAG target and PASS on a hardened RAG target."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    # 1. Vulnerable RAG Pipeline Target
    vuln_rag = TargetProfile(
        organization_id=org_alpha.id,
        name="Vulnerable Multi-Tenant RAG Pipeline",
        architecture_type=ArchitectureTypeEnum.RAG_PIPELINE.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/vulnerable",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.DUAL_TENANT_BEARER.value,
        encrypted_credentials=encrypt_credentials(
            {
                "tenant_a_token": "sk-proj-tenantAlphaSecretToken111",
                "tenant_b_token": "sk-proj-tenantBetaSecretToken222",
            },
            organization_id=org_alpha.id,
        ),
        request_template={"simulator_profile": "vulnerable"},
        rag_harness_config={
            "tenant_a_id": "tenant-alpha",
            "tenant_b_id": "tenant-beta",
            "canary_token": "AEGIS-CANARY-TENANT-A-9F8A2C",
            "enforce_tenant_filter": False,
            "chunk_size": 4096,
            "sanitize_ingested_documents": False,
        },
    )
    db_session.add(vuln_rag)

    # 2. Hardened RAG Pipeline Target
    hard_rag = TargetProfile(
        organization_id=org_alpha.id,
        name="Hardened Multi-Tenant RAG Pipeline",
        architecture_type=ArchitectureTypeEnum.RAG_PIPELINE.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/hardened",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.DUAL_TENANT_BEARER.value,
        request_template={"simulator_profile": "hardened"},
        rag_harness_config={
            "tenant_a_id": "tenant-alpha",
            "tenant_b_id": "tenant-beta",
            "canary_token": "AEGIS-CANARY-TENANT-A-9F8A2C",
            "enforce_tenant_filter": True,
            "chunk_size": 512,
            "sanitize_ingested_documents": True,
        },
    )
    db_session.add(hard_rag)
    db_session.commit()

    vuln_assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=vuln_rag.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Phase 5 Vulnerable RAG Assessment",
        selected_modules=["RAG"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "authorizer_name": "Alpha Engineer"},
    )
    hard_assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=hard_rag.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Phase 5 Hardened RAG Assessment",
        selected_modules=["RAG"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "authorizer_name": "Alpha Engineer"},
    )
    db_session.add_all([vuln_assessment, hard_assessment])
    db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    # Run vulnerable RAG assessment
    completed_vuln = await orchestrator.run_assessment(vuln_assessment.id)
    assert completed_vuln.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_vuln.total_tests_planned == 4
    assert completed_vuln.tests_completed == 4
    assert len(completed_vuln.findings) == 4

    vuln_results = {r.test_id: r for r in completed_vuln.test_results}
    assert sorted(vuln_results.keys()) == EXPECTED_RAG_TEST_IDS
    for test_id in EXPECTED_RAG_TEST_IDS:
        assert vuln_results[test_id].execution_status == ExecutionStatus.FAIL.value
        assert vuln_results[test_id].vulnerability_status == VulnerabilityStatus.VULNERABLE.value

    # Verify RAG-ARCH-001 recorded both runtime exploitation and static config weaknesses
    arch_log = vuln_results["RAG-ARCH-001"].execution_log
    assert arch_log["runtime_exploited_count"] == 1
    assert arch_log["static_config_weakness_count"] == 3

    # Run hardened RAG assessment
    completed_hard = await orchestrator.run_assessment(hard_assessment.id)
    assert completed_hard.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_hard.total_tests_planned == 4
    assert completed_hard.tests_completed == 4
    assert len(completed_hard.findings) == 0
    assert completed_hard.posture_grade == "A"
    for res in completed_hard.test_results:
        assert res.execution_status == ExecutionStatus.PASS.value
        assert res.vulnerability_status == VulnerabilityStatus.SECURE.value


@pytest.mark.asyncio
async def test_module_b_rag_harness_adapter_dual_tenant_redaction_and_config_distinction(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify RAGHarnessAdapter with DUAL_TENANT_BEARER credentials sends both tenant tokens on wire, sanitizes HTTP evidence, and distinguishes static config weaknesses from runtime security."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    observed_auth_headers: list[str] = []

    def _rag_mock_handler(request: httpx.Request) -> httpx.Response:
        observed_auth_headers.append(request.headers.get("Authorization", ""))
        body_text = request.content.decode("utf-8", errors="ignore")
        # Trigger an HTTP FAIL on RAG-META-001 ($ne filter probe) so we can verify HTTP TechnicalEvidence redaction
        if "$ne" in body_text:
            return httpx.Response(
                200,
                json={
                    "answer": "Board merger terms: AEGIS_VERIFY_TOKEN_META_BYPASS_771",
                    "retrieved_chunks": [
                        {
                            "chunk_id": "exec-board-99",
                            "tenant_id": "tenant-alpha",
                            "classification": "RESTRICTED_EXECUTIVE",
                            "text": "AEGIS_VERIFY_TOKEN_META_BYPASS_771",
                        }
                    ],
                    "citations": ["exec-board-99"],
                },
            )
        # Runtime endpoint is properly isolated for tenant-beta on RAG-AUTH-001 and RAG-IPI-001
        return httpx.Response(
            200,
            json={
                "answer": "Safe tenant-beta knowledge response.",
                "retrieved_chunks": [
                    {
                        "chunk_id": "beta-doc-10",
                        "tenant_id": "tenant-beta",
                        "classification": "PUBLIC",
                        "text": "Authorized tenant-beta content.",
                    }
                ],
                "citations": ["beta-doc-10"],
            },
        )

    transport = httpx.MockTransport(_rag_mock_handler)

    rag_target = TargetProfile(
        organization_id=org_alpha.id,
        name="External Assisted RAG Harness Target",
        architecture_type=ArchitectureTypeEnum.RAG_PIPELINE.value,
        integration_mode=IntegrationModeEnum.ASSISTED_HARNESS.value,
        endpoint_url="https://rag.customer.example.com/v1/query",
        allowed_hosts=["rag.customer.example.com"],
        auth_type=AuthTypeEnum.DUAL_TENANT_BEARER.value,
        encrypted_credentials=encrypt_credentials(
            {
                "tenant_a_token": "sk-proj-liveTenantASecret999999",
                "tenant_b_token": "sk-proj-liveTenantBSecret888888",
            },
            organization_id=org_alpha.id,
        ),
        rag_harness_config={
            "tenant_a_id": "tenant-alpha",
            "tenant_b_id": "tenant-beta",
            "canary_token": "AEGIS-CANARY-TENANT-A-9F8A2C",
            "enforce_tenant_filter": True,
            "chunk_size": 4096,  # Triggers CFG-RAG-002 static weakness only!
            "sanitize_ingested_documents": True,
        },
        rate_limit_rps=50.0,
    )
    db_session.add(rag_target)
    db_session.commit()

    assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=rag_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="RAG Harness Static vs Runtime Distinction Scan",
        selected_modules=["RAG"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    db_session.add(assessment)
    db_session.commit()

    orchestrator = AssessmentOrchestrator(
        db_session, transport=transport, resolve_dns=False
    )
    completed = await orchestrator.run_assessment(assessment.id)

    # 1. Verify DUAL_TENANT_BEARER sent both Tenant A (primary) and Tenant B (secondary) tokens on the wire
    assert "Bearer sk-proj-liveTenantASecret999999" in observed_auth_headers
    assert "Bearer sk-proj-liveTenantBSecret888888" in observed_auth_headers

    results_by_id = {r.test_id: r for r in completed.test_results}
    # RAG-AUTH-001 and RAG-IPI-001 PASS because the mock endpoint properly isolates tenant-beta
    assert results_by_id["RAG-AUTH-001"].execution_status == ExecutionStatus.PASS.value
    assert results_by_id["RAG-IPI-001"].execution_status == ExecutionStatus.PASS.value
    assert results_by_id["RAG-META-001"].execution_status == ExecutionStatus.FAIL.value

    # RAG-ARCH-001 FAILS strictly due to static config weakness (CFG-RAG-002), with runtime_exploited_count == 0
    arch_res = results_by_id["RAG-ARCH-001"]
    assert arch_res.execution_status == ExecutionStatus.FAIL.value
    assert arch_res.execution_log["runtime_exploited_count"] == 0
    assert arch_res.execution_log["static_config_weakness_count"] == 1

    findings_by_id = {f.test_id: f for f in completed.findings}
    assert sorted(findings_by_id.keys()) == ["RAG-ARCH-001", "RAG-META-001"]

    # 2. Verify static config finding vs. runtime HTTP finding and verify credential redaction in persisted HTTP evidence
    arch_finding = findings_by_id["RAG-ARCH-001"]
    assert arch_finding.evidence_items[0].detector_name == "CONFIG_RULE"
    assert "STATIC_CONFIG_WEAKNESS (CFG-RAG-002)" in arch_finding.evidence_items[0].matched_artifacts[0]

    meta_finding = findings_by_id["RAG-META-001"]
    meta_ev = meta_finding.evidence_items[0]
    assert meta_ev.request_payload["headers"]["Authorization"] == "[REDACTED_CREDENTIAL]"
    assert "sk-proj-liveTenantASecret999999" not in str(meta_ev.request_payload)
    assert "sk-proj-liveTenantBSecret888888" not in str(meta_ev.request_payload)


# ---------------------------------------------------------------------------
# 4. Module C (AI Agent Security Scanner) & Safety Gate Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_module_c_agent_scanners_on_vulnerable_and_hardened_targets(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify all 3 Agent scanners detect vulnerabilities on a vulnerable Agent target and PASS on a hardened Agent target."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    vuln_agent = TargetProfile(
        organization_id=org_alpha.id,
        name="Vulnerable Autonomous AI Agent",
        architecture_type=ArchitectureTypeEnum.AI_AGENT.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/vulnerable",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
        request_template={"simulator_profile": "vulnerable"},
        agent_harness_config={
            "human_in_the_loop": False,
            "max_iterations": 50,
            "tools": [
                {
                    "name": "aegis_canary_diagnostics_read",
                    "parameters": {"type": "object", "additionalProperties": True},
                }
            ],
        },
    )
    hard_agent = TargetProfile(
        organization_id=org_alpha.id,
        name="Hardened Enterprise AI Agent",
        architecture_type=ArchitectureTypeEnum.AI_AGENT.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/hardened",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
        request_template={"simulator_profile": "hardened"},
        agent_harness_config={
            "human_in_the_loop": True,
            "max_iterations": 10,
            "tools": [
                {
                    "name": "aegis_canary_diagnostics_read",
                    "parameters": {"type": "object", "additionalProperties": False},
                }
            ],
        },
    )
    db_session.add_all([vuln_agent, hard_agent])
    db_session.commit()

    vuln_assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=vuln_agent.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Phase 5 Vulnerable Agent Scan",
        selected_modules=["AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    hard_assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=hard_agent.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Phase 5 Hardened Agent Scan",
        selected_modules=["AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    db_session.add_all([vuln_assessment, hard_assessment])
    db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    completed_vuln = await orchestrator.run_assessment(vuln_assessment.id)
    assert completed_vuln.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_vuln.total_tests_planned == 3
    assert completed_vuln.tests_completed == 3
    assert len(completed_vuln.findings) == 3

    vuln_results = {r.test_id: r for r in completed_vuln.test_results}
    assert sorted(vuln_results.keys()) == EXPECTED_AGENT_TEST_IDS
    for test_id in EXPECTED_AGENT_TEST_IDS:
        assert vuln_results[test_id].execution_status == ExecutionStatus.FAIL.value
        assert vuln_results[test_id].vulnerability_status == VulnerabilityStatus.VULNERABLE.value

    # Verify AGT-PERM-001 recorded both runtime HITL bypass and all 3 static CFG-AGT-* rules
    perm_log = vuln_results["AGT-PERM-001"].execution_log
    assert perm_log["runtime_exploited_count"] == 1
    assert perm_log["static_config_weakness_count"] == 3

    completed_hard = await orchestrator.run_assessment(hard_assessment.id)
    assert completed_hard.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_hard.total_tests_planned == 3
    assert completed_hard.tests_completed == 3
    assert len(completed_hard.findings) == 0
    assert completed_hard.posture_grade == "A"
    for res in completed_hard.test_results:
        assert res.execution_status == ExecutionStatus.PASS.value
        assert res.vulnerability_status == VulnerabilityStatus.SECURE.value


@pytest.mark.asyncio
async def test_agent_mutating_risk_safety_gate_and_architecture_not_applicable(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify external Agent targets without sandbox/dry-run attestation record NOT_APPLICABLE and send 0 agent probes."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    probe_counter = {"count": 0}

    def _external_agent_handler(request: httpx.Request) -> httpx.Response:
        probe_counter["count"] += 1
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Ready."},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    transport = httpx.MockTransport(_external_agent_handler)

    # 1. External OPENAI_COMPAT Agent Target WITHOUT sandbox confirmation or dry_run flag
    unattested_agent_target = TargetProfile(
        organization_id=org_alpha.id,
        name="External Production Agent Without Sandbox Attestation",
        architecture_type=ArchitectureTypeEnum.AI_AGENT.value,
        integration_mode=IntegrationModeEnum.OPENAI_COMPAT.value,
        endpoint_url="https://agent.customer.example.com/v1/chat/completions",
        allowed_hosts=["agent.customer.example.com"],
        auth_type=AuthTypeEnum.NONE.value,
        agent_harness_config={"dry_run": False, "human_in_the_loop": True, "max_iterations": 10},
        rate_limit_rps=50.0,
    )
    db_session.add(unattested_agent_target)
    db_session.commit()

    assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=unattested_agent_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Unconfirmed Agent Sandbox Safety Check",
        selected_modules=["AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={
            "authorized": True,
            "agent_sandbox_confirmed": False,  # Not confirmed!
        },
    )
    db_session.add(assessment)
    db_session.commit()

    orchestrator = AssessmentOrchestrator(
        db_session, transport=transport, resolve_dns=False
    )
    completed = await orchestrator.run_assessment(assessment.id)

    assert completed.status == AssessmentStatusEnum.COMPLETED.value
    # Only the 1 baseline TargetProfiler ping was sent; 0 active agent test probes were sent!
    assert probe_counter["count"] == 1
    assert completed.summary_metrics["status_counts"]["NOT_APPLICABLE"] == 3
    for res in completed.test_results:
        assert res.execution_status == ExecutionStatus.NOT_APPLICABLE.value
        assert res.vulnerability_status == VulnerabilityStatus.UNDETERMINED.value
        assert res.probes_sent == 0
        assert "mutating risk" in res.execution_log["applicability_note"]

    # 2. Architecture Mismatch: Running RAG and AGENT modules against an LLM_APP target -> all 7 NOT_APPLICABLE
    llm_only_target = TargetProfile(
        organization_id=org_alpha.id,
        name="Standalone LLM App Target",
        architecture_type=ArchitectureTypeEnum.LLM_APP.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/vulnerable",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
    )
    # 3. CONFIG_ONLY Integration Mode on HYBRID target -> active-only suites are NOT_APPLICABLE,
    #    while RAG-ARCH-001 and AGT-PERM-001 evaluate static config rules ONLY (runtime_exploited_count == 0)
    config_only_target = TargetProfile(
        organization_id=org_alpha.id,
        name="Static Config-Only Hybrid Target",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.CONFIG_ONLY.value,
        endpoint_url="https://api.customer.example.com/v1/chat",
        allowed_hosts=["api.customer.example.com"],
        auth_type=AuthTypeEnum.NONE.value,
        rag_harness_config={
            "enforce_tenant_filter": False,
            "chunk_size": 512,
            "sanitize_ingested_documents": True,
        },
        agent_harness_config={
            "human_in_the_loop": False,
            "max_iterations": 10,
            "tools": [],
        },
    )
    db_session.add_all([llm_only_target, config_only_target])
    db_session.commit()

    arch_na_scan = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=llm_only_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Architecture Mismatch NOT_APPLICABLE Scan",
        selected_modules=["RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    cfg_only_scan = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=config_only_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Static Config-Only Hybrid Scan",
        selected_modules=["RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    db_session.add_all([arch_na_scan, cfg_only_scan])
    db_session.commit()

    orchestrator_default = AssessmentOrchestrator(db_session)
    completed_arch_na = await orchestrator_default.run_assessment(arch_na_scan.id)
    assert completed_arch_na.summary_metrics["status_counts"]["NOT_APPLICABLE"] == 7
    for res in completed_arch_na.test_results:
        assert res.execution_status == ExecutionStatus.NOT_APPLICABLE.value
        assert res.probes_sent == 0
        assert "requires architecture" in res.execution_log["applicability_note"]

    completed_cfg_only = await orchestrator_default.run_assessment(cfg_only_scan.id)
    cfg_results = {r.test_id: r for r in completed_cfg_only.test_results}
    for active_id in ("RAG-AUTH-001", "RAG-IPI-001", "RAG-META-001", "AGT-TOOL-001", "AGT-GH-001"):
        assert cfg_results[active_id].execution_status == ExecutionStatus.NOT_APPLICABLE.value
        assert cfg_results[active_id].probes_sent == 0
    for hybrid_id in ("RAG-ARCH-001", "AGT-PERM-001"):
        assert cfg_results[hybrid_id].execution_status == ExecutionStatus.FAIL.value
        assert cfg_results[hybrid_id].probes_sent == 0
        assert cfg_results[hybrid_id].execution_log["runtime_exploited_count"] == 0
        assert cfg_results[hybrid_id].execution_log["static_config_weakness_count"] == 1


@pytest.mark.asyncio
async def test_rag_and_agent_ambiguous_and_upstream_error_profiles(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify RAG and Agent scanners record NEEDS_REVIEW on ambiguous responses and ERROR (never PASS) on 5xx and timeout profiles."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    amb_hybrid = TargetProfile(
        organization_id=org_alpha.id,
        name="Ambiguous Hybrid RAG+Agent Target",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/ambiguous",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
        request_template={"simulator_profile": "ambiguous"},
        rag_harness_config={
            "enforce_tenant_filter": True,
            "chunk_size": 512,
            "sanitize_ingested_documents": True,
        },
        agent_harness_config={
            "human_in_the_loop": True,
            "max_iterations": 10,
            "tools": [],
        },
    )
    err_hybrid = TargetProfile(
        organization_id=org_alpha.id,
        name="Error 500 Hybrid RAG+Agent Target",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/error_500",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
        request_template={"simulator_profile": "error_500"},
    )
    timeout_hybrid = TargetProfile(
        organization_id=org_alpha.id,
        name="Timeout Hybrid RAG+Agent Target",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/timeout",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
        request_template={"simulator_profile": "timeout"},
    )
    db_session.add_all([amb_hybrid, err_hybrid, timeout_hybrid])
    db_session.commit()

    amb_scan = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=amb_hybrid.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Ambiguous RAG+Agent Scan",
        selected_modules=["RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    err_scan = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=err_hybrid.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Error 500 RAG+Agent Scan",
        selected_modules=["RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    timeout_scan = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=timeout_hybrid.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Timeout RAG+Agent Scan",
        selected_modules=["RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    db_session.add_all([amb_scan, err_scan, timeout_scan])
    db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    completed_amb = await orchestrator.run_assessment(amb_scan.id)
    assert completed_amb.summary_metrics["status_counts"]["NEEDS_REVIEW"] == 7
    assert len(completed_amb.findings) == 7
    assert all(f.is_confirmed is False for f in completed_amb.findings)

    completed_err = await orchestrator.run_assessment(err_scan.id)
    assert completed_err.summary_metrics["status_counts"]["ERROR"] == 7
    assert completed_err.summary_metrics["status_counts"]["PASS"] == 0
    assert len(completed_err.findings) == 0

    completed_timeout = await orchestrator.run_assessment(timeout_scan.id)
    assert completed_timeout.summary_metrics["status_counts"]["ERROR"] == 7
    assert completed_timeout.summary_metrics["status_counts"]["PASS"] == 0
    assert len(completed_timeout.findings) == 0
    for res in completed_timeout.test_results:
        assert res.execution_status == ExecutionStatus.ERROR.value
        assert res.vulnerability_status == VulnerabilityStatus.UNDETERMINED.value


# ---------------------------------------------------------------------------
# 5. Full Combined Assessment (LLM + RAG + AGENT = 13 Suites) via FastAPI Endpoints
# ---------------------------------------------------------------------------


def test_combined_llm_rag_agent_13_suite_assessment_via_api(
    client: TestClient,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify full 13-suite combined assessment (LLM + RAG + AGENT) via /api/v1/assessments."""
    tokens = multi_tenant_seed["tokens"]
    headers = {"Authorization": f"Bearer {tokens['alpha_engineer']}"}

    # 1. Create a HYBRID vulnerable target profile
    target_resp = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Acme Enterprise Hybrid AI Copilot (LLM + RAG + Agent)",
            "architecture_type": "HYBRID",
            "integration_mode": "SIMULATOR",
            "endpoint_url": "https://simulator.aegis.internal/vulnerable",
            "allowed_hosts": ["simulator.aegis.internal"],
            "auth_type": "DUAL_TENANT_BEARER",
            "credentials": {
                "tenant_a_token": "sk-proj-alphaTenantToken123456",
                "tenant_b_token": "sk-proj-betaTenantToken654321",
            },
            "request_template": {"simulator_profile": "vulnerable"},
            "architecture_manifest": {"temperature": 1.3},
            "rag_harness_config": {
                "tenant_a_id": "tenant-alpha",
                "tenant_b_id": "tenant-beta",
                "canary_token": "AEGIS-CANARY-TENANT-A-9F8A2C",
                "enforce_tenant_filter": False,
                "chunk_size": 4096,
            },
            "agent_harness_config": {
                "human_in_the_loop": False,
                "max_iterations": 40,
            },
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 2. Create combined LLM + RAG + AGENT assessment
    create_resp = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Full 13-Suite Enterprise AI Security Assessment",
            "target_profile_id": target_id,
            "selected_modules": ["LLM", "RAG", "AGENT"],
            "scope_attestation": {
                "authorized": True,
                "authorizer_name": "Principal Security Engineer",
                "agent_sandbox_confirmed": True,
            },
        },
    )
    assert create_resp.status_code == 201
    assessment_id = create_resp.json()["id"]

    # 3. Execute assessment via API
    run_resp = client.post(
        f"/api/v1/assessments/{assessment_id}/run",
        headers=headers,
    )
    assert run_resp.status_code == 200
    body = run_resp.json()

    assert body["status"] == "COMPLETED"
    assert body["total_tests_planned"] == 13
    assert body["tests_completed"] == 13
    assert body["summary_metrics"]["status_counts"]["FAIL"] == 13
    assert len(body["findings"]) == 13

    executed_ids = sorted(r["test_id"] for r in body["test_results"])
    assert executed_ids == EXPECTED_ALL_13_TEST_IDS
