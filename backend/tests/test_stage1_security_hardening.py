"""Stage 1 Backend Security & Contract Hardening Verification Suite.

Covers Tasks A through F:
- Task A: CONFIG_ONLY assessments never execute active probes or fabricate runtime findings; target creation skips DNS for CONFIG_ONLY/SIMULATOR; static config findings are preserved even when active transport fails.
- Task B: Production/staging secret validation rejects default, empty, or short JWT and master encryption keys without leaking secret values.
- Task C: Unified secret redaction across logging.py, audit.py, and evidence.py covering token keys, nested dicts/lists/tuples, API keys, JWTs, AWS keys, and passwords.
- Task D: Assessment selected_modules validation against ScannerModule and zero-test posture guard.
- Task E: Atomic assessment execution claim preventing concurrent duplicate runs and recovering cleanly from interrupted executions.
- Task F: DNS rebinding / TOCTOU protection via IP-pinned outbound connections preserving HTTP Host header and TLS SNI hostname.
"""

import asyncio
import socket
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.audit import record_audit_event
from app.core.config import Settings
from app.core.exceptions import ScopeViolationError
from app.core.logging import redact_sensitive_text
from app.engine.adapters import BuiltInTargetSimulator, OpenAICompatibleAdapter, SafeTargetClient
from app.engine.contracts import (
    BaseSecurityTest,
    ExecutionStatus,
    NormalizedTestResult,
    ScannerModule,
    TestContext,
    VulnerabilityStatus,
)
from app.engine.evidence import detect_and_mask_sensitive_artifacts, sanitize_payload
from app.engine.orchestrator import AssessmentOrchestrator
from app.engine.registry import SecurityTestRegistry, register_security_test
from app.models.assessment import Assessment, AssessmentStatusEnum
from app.models.target import (
    ArchitectureTypeEnum,
    AuthTypeEnum,
    IntegrationModeEnum,
    TargetProfile,
)

# ---------------------------------------------------------------------------
# Task A: CONFIG_ONLY & Target Creation Regression Tests
# ---------------------------------------------------------------------------


def test_target_creation_skips_dns_for_config_only_and_simulator(
    client: TestClient,
    multi_tenant_seed: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify POST /api/v1/targets does not perform DNS resolution for CONFIG_ONLY or SIMULATOR targets."""
    tokens = multi_tenant_seed["tokens"]
    headers = {"Authorization": f"Bearer {tokens['alpha_engineer']}"}

    def _forbid_dns(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("DNS resolution must not be invoked for SIMULATOR or CONFIG_ONLY targets")

    monkeypatch.setattr(socket, "getaddrinfo", _forbid_dns)

    for mode in ("SIMULATOR", "CONFIG_ONLY"):
        resp = client.post(
            "/api/v1/targets",
            headers=headers,
            json={
                "name": f"Offline {mode} Target",
                "architecture_type": "LLM_APP",
                "integration_mode": mode,
                "endpoint_url": "https://nonexistent-offline-host.internal.invalid/v1/chat",
                "allowed_hosts": ["nonexistent-offline-host.internal.invalid"],
                "auth_type": "NONE",
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["integration_mode"] == mode


@pytest.mark.asyncio
async def test_config_only_llm_module_never_executes_probes_or_fabricates_runtime_findings(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Prove CONFIG_ONLY assessments send 0 active probes and never fabricate runtime findings across LLM, RAG, and AGENT."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    # 1. Hardened manifest in CONFIG_ONLY mode -> 0 probes sent, 0 findings, Grade A
    hardened_cfg_target = TargetProfile(
        organization_id=org_alpha.id,
        name="Hardened Config-Only LLM Target",
        architecture_type=ArchitectureTypeEnum.LLM_APP.value,
        integration_mode=IntegrationModeEnum.CONFIG_ONLY.value,
        endpoint_url="https://vulnerable-looking-url.example.com/v1/chat",
        allowed_hosts=["vulnerable-looking-url.example.com"],
        auth_type=AuthTypeEnum.NONE.value,
        architecture_manifest={
            "system_prompt": "You are a helpful banking assistant.",
            "model_config": {"max_tokens": 1024, "temperature": 0.2},
            "input_guardrail_enabled": True,
            "output_sanitization_enabled": True,
        },
    )
    # 2. Weak manifest in CONFIG_ONLY mode -> 0 probes sent, deterministic CONFIG_RULE findings only
    weak_cfg_target = TargetProfile(
        organization_id=org_alpha.id,
        name="Weak Config-Only Hybrid Target",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.CONFIG_ONLY.value,
        endpoint_url="https://hardened-looking-url.example.com/v1/chat",
        allowed_hosts=["hardened-looking-url.example.com"],
        auth_type=AuthTypeEnum.NONE.value,
        architecture_manifest={
            "system_prompt": "System secret key: AKIAIOSFODNN7EXAMPLE",
            "model_config": {"max_tokens": 8192, "temperature": 1.5},
        },
        rag_harness_config={
            "enforce_tenant_filter": False,
            "chunk_size": 4096,
            "sanitize_ingested_documents": False,
        },
        agent_harness_config={
            "human_in_the_loop": False,
            "max_iterations": 50,
            "tools": [
                {
                    "name": "admin_tool",
                    "parameters": {"type": "object", "additionalProperties": True},
                }
            ],
        },
    )
    db_session.add_all([hardened_cfg_target, weak_cfg_target])
    db_session.commit()

    hard_asmt = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=hardened_cfg_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Config-Only Hardened LLM Assessment",
        selected_modules=["LLM"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    weak_asmt = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=weak_cfg_target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Config-Only Weak Hybrid Assessment",
        selected_modules=["LLM", "RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    db_session.add_all([hard_asmt, weak_asmt])
    db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session)

    completed_hard = await orchestrator.run_assessment(hard_asmt.id)
    assert completed_hard.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_hard.summary_metrics["total_probes_sent"] == 0
    assert len(completed_hard.findings) == 0
    assert completed_hard.posture_grade == "A"

    hard_res_by_id = {r.test_id: r for r in completed_hard.test_results}
    for active_llm_id in ("LLM-PI-001", "LLM-PI-002", "LLM-SID-001", "LLM-IOH-001"):
        assert hard_res_by_id[active_llm_id].execution_status == ExecutionStatus.NOT_APPLICABLE.value
        assert hard_res_by_id[active_llm_id].probes_sent == 0
    for hybrid_llm_id in ("LLM-SPE-001", "LLM-CFG-001"):
        assert hard_res_by_id[hybrid_llm_id].execution_status == ExecutionStatus.PASS.value
        assert hard_res_by_id[hybrid_llm_id].probes_sent == 0
        assert hard_res_by_id[hybrid_llm_id].execution_log["runtime_exploited_count"] == 0

    completed_weak = await orchestrator.run_assessment(weak_asmt.id)
    assert completed_weak.status == AssessmentStatusEnum.COMPLETED.value
    assert completed_weak.summary_metrics["total_probes_sent"] == 0
    weak_findings_by_id = {f.test_id: f for f in completed_weak.findings}
    assert sorted(weak_findings_by_id.keys()) == [
        "AGT-PERM-001",
        "LLM-CFG-001",
        "LLM-SPE-001",
        "RAG-ARCH-001",
    ]
    for f in completed_weak.findings:
        assert all(ev.detector_name == "CONFIG_RULE" for ev in f.evidence_items)

    # Also verify BuiltInTargetSimulator directly rejects send_prompt when integration_mode=="CONFIG_ONLY"
    cfg_sim = BuiltInTargetSimulator(integration_mode="CONFIG_ONLY")
    with pytest.raises(RuntimeError, match="CONFIG_ONLY"):
        await cfg_sim.send_prompt("Should not execute")


@pytest.mark.asyncio
async def test_static_config_findings_preserved_when_active_transport_fails(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify deterministic static config findings are preserved even when active HTTP probes return 503."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    def _failing_503_transport(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "Upstream model worker unavailable"})

    target = TargetProfile(
        organization_id=org_alpha.id,
        name="503 Target With Static Weaknesses",
        architecture_type=ArchitectureTypeEnum.HYBRID.value,
        integration_mode=IntegrationModeEnum.OPENAI_COMPAT.value,
        endpoint_url="https://api.customer.example.com/v1/chat/completions",
        allowed_hosts=["api.customer.example.com"],
        auth_type=AuthTypeEnum.NONE.value,
        architecture_manifest={
            "system_prompt": "Embedded AWS key AKIAIOSFODNN7EXAMPLE",
            "model_config": {"max_tokens": 8192, "temperature": 1.4},
        },
        rag_harness_config={"enforce_tenant_filter": False, "chunk_size": 4096},
        agent_harness_config={"human_in_the_loop": False, "max_iterations": 40},
        rate_limit_rps=50.0,
    )
    db_session.add(target)
    db_session.commit()

    assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Transport Failure Static Preservation Scan",
        selected_modules=["LLM", "RAG", "AGENT"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True, "agent_sandbox_confirmed": True},
    )
    db_session.add(assessment)
    db_session.commit()

    orchestrator = AssessmentOrchestrator(
        db_session,
        transport=httpx.MockTransport(_failing_503_transport),
        resolve_dns=False,
    )
    completed = await orchestrator.run_assessment(assessment.id)

    findings_by_id = {f.test_id: f for f in completed.findings}
    # All 4 hybrid config-auditing suites preserved their static CONFIG_RULE findings despite HTTP 503
    for cfg_test_id in ("LLM-SPE-001", "LLM-CFG-001", "RAG-ARCH-001", "AGT-PERM-001"):
        assert cfg_test_id in findings_by_id
        assert all(ev.detector_name == "CONFIG_RULE" for ev in findings_by_id[cfg_test_id].evidence_items)

    # Purely active tests recorded ERROR (UNDETERMINED), never PASS
    res_by_id = {r.test_id: r for r in completed.test_results}
    for active_id in ("LLM-PI-001", "LLM-PI-002", "LLM-SID-001", "LLM-IOH-001", "RAG-AUTH-001", "AGT-TOOL-001"):
        assert res_by_id[active_id].execution_status == ExecutionStatus.ERROR.value
        assert res_by_id[active_id].vulnerability_status == VulnerabilityStatus.UNDETERMINED.value


# ---------------------------------------------------------------------------
# Task B: Production Secret Validation Tests
# ---------------------------------------------------------------------------


def test_production_and_staging_reject_default_missing_or_short_secrets() -> None:
    """Verify Settings rejects default/weak secrets in production/staging without printing secret values."""
    # 1. Development and test environments remain usable with defaults
    dev_settings = Settings(AEGIS_ENV="development")
    assert dev_settings.aegis_env == "development"
    test_settings = Settings(AEGIS_ENV="test")
    assert test_settings.aegis_env == "test"

    # 2. Empty secrets are rejected in any environment
    with pytest.raises(ValidationError, match="AEGIS_JWT_SECRET_KEY must not be empty"):
        Settings(AEGIS_ENV="development", AEGIS_JWT_SECRET_KEY="   ")

    with pytest.raises(ValidationError, match="AEGIS_MASTER_ENCRYPTION_KEY must not be empty"):
        Settings(AEGIS_ENV="development", AEGIS_MASTER_ENCRYPTION_KEY="")

    # 3. Default JWT secret or default master key rejected in production and staging
    valid_jwt = "prod-jwt-high-entropy-key-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f"
    valid_master = "prod-master-encryption-key-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"

    for env_name in ("production", "staging"):
        with pytest.raises(ValidationError) as exc_jwt:
            Settings(AEGIS_ENV=env_name, AEGIS_MASTER_ENCRYPTION_KEY=valid_master)
        assert "AEGIS_JWT_SECRET_KEY" in str(exc_jwt.value)
        assert "do-not-use-in-production" not in str(exc_jwt.value)

        with pytest.raises(ValidationError) as exc_master:
            Settings(AEGIS_ENV=env_name, AEGIS_JWT_SECRET_KEY=valid_jwt)
        assert "AEGIS_MASTER_ENCRYPTION_KEY" in str(exc_master.value)
        assert "9f8a7b6c5d4e3f" not in str(exc_master.value)

        # Short secret (< 32 chars) rejected without echoing secret value
        short_secret = "my-short-secret-value-123"
        with pytest.raises(ValidationError) as exc_short:
            Settings(
                AEGIS_ENV=env_name,
                AEGIS_JWT_SECRET_KEY=short_secret,
                AEGIS_MASTER_ENCRYPTION_KEY=valid_master,
            )
        assert short_secret not in str(exc_short.value)

        # 4. Valid explicitly configured secrets succeed in production and staging
        prod_ok = Settings(
            AEGIS_ENV=env_name,
            AEGIS_JWT_SECRET_KEY=valid_jwt,
            AEGIS_MASTER_ENCRYPTION_KEY=valid_master,
        )
        assert prod_ok.aegis_env == env_name


# ---------------------------------------------------------------------------
# Task C: Unified Secret Redaction Consistency Tests
# ---------------------------------------------------------------------------


def test_unified_secret_redaction_nested_containers_and_token_keys(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify unified redaction across logging, audit, and evidence for tokens, JWTs, AWS keys, passwords, and nested lists/tuples."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_admin = multi_tenant_seed["alpha_admin"]

    # Construct synthetic test values dynamically so no literal secret patterns sit in logs
    synthetic_jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ1c2VyIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    synthetic_aws = "ASIA" + "IOSFODNN7EXAMPLE"
    synthetic_ghp = "ghp_" + "1234567890abcdefghijklmnopqrstuv"
    synthetic_opaque_token = "opaque-custom-auth-val-9988776655"
    synthetic_pw = "SuperConfidentialPass!2026"

    nested_payload = {
        "token": synthetic_opaque_token,
        "auth_token": synthetic_opaque_token,
        "session_token": synthetic_opaque_token,
        "password": synthetic_pw,
        "max_tokens": 1024,
        "canary_token": "AEGIS-CANARY-SAFE-001",
        "credential_preview": "sk-pro****...1234",
        "scope_attestation_hash": "sha256:abcdef1234567890",
        "nested_list": [
            {"client_secret": synthetic_pw, "custom_api_token": synthetic_opaque_token},
            (f"Bearer {synthetic_opaque_token}", f"Key={synthetic_aws}", synthetic_ghp, synthetic_jwt),
        ],
        "tokens_list": [synthetic_opaque_token, "second-opaque-token"],
    }

    # 1. Verify evidence.sanitize_payload
    sanitized_ev = sanitize_payload(nested_payload)
    assert sanitized_ev["token"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["auth_token"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["session_token"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["password"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["max_tokens"] == 1024
    assert sanitized_ev["canary_token"] == "AEGIS-CANARY-SAFE-001"
    assert sanitized_ev["credential_preview"] == "sk-pro****...1234"
    assert sanitized_ev["nested_list"][0]["client_secret"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["nested_list"][0]["custom_api_token"] == "[REDACTED_CREDENTIAL]"
    assert sanitized_ev["tokens_list"] == ["[REDACTED_CREDENTIAL]", "[REDACTED_CREDENTIAL]"]
    serialized_ev = str(sanitized_ev)
    for secret_val in (synthetic_opaque_token, synthetic_pw, synthetic_aws, synthetic_ghp, synthetic_jwt):
        assert secret_val not in serialized_ev

    # 2. Verify audit.record_audit_event with nested lists/tuples/dicts
    audit_log = record_audit_event(
        db_session,
        organization_id=org_alpha.id,
        user_id=alpha_admin.id,
        action="SECURITY_REDACTION_VERIFY",
        resource_type="TARGET_PROFILE",
        resource_id="target-001",
        details=nested_payload,
    )
    assert audit_log.details_json["token"] == "[REDACTED]"
    assert audit_log.details_json["password"] == "[REDACTED]"
    assert audit_log.details_json["nested_list"][0]["client_secret"] == "[REDACTED]"
    assert audit_log.details_json["tokens_list"] == ["[REDACTED]", "[REDACTED]"]
    serialized_audit = str(audit_log.details_json)
    for secret_val in (synthetic_opaque_token, synthetic_pw, synthetic_aws, synthetic_ghp, synthetic_jwt):
        assert secret_val not in serialized_audit

    # 3. Verify logging.redact_sensitive_text and detect_and_mask_sensitive_artifacts
    redacted_str = redact_sensitive_text(
        f"aws={synthetic_aws} gh={synthetic_ghp} jwt={synthetic_jwt} password={synthetic_pw}"
    )
    for secret_val in (synthetic_aws, synthetic_ghp, synthetic_jwt, synthetic_pw):
        assert secret_val not in redacted_str

    masked_artifacts = detect_and_mask_sensitive_artifacts(f"{synthetic_aws} {synthetic_ghp}")
    assert any("AWS Access Key ID" in m for m in masked_artifacts)
    assert any("GitHub Token" in m for m in masked_artifacts)


# ---------------------------------------------------------------------------
# Task D: Assessment Input Validation Tests
# ---------------------------------------------------------------------------


def test_assessment_selected_modules_validation(
    client: TestClient,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify selected_modules accepts valid ScannerModule values and rejects unsupported modules with 422."""
    tokens = multi_tenant_seed["tokens"]
    headers = {"Authorization": f"Bearer {tokens['alpha_engineer']}"}

    target_resp = client.post(
        "/api/v1/targets",
        headers=headers,
        json={
            "name": "Module Validation Target",
            "architecture_type": "HYBRID",
            "integration_mode": "SIMULATOR",
            "endpoint_url": "https://simulator.aegis.internal/hardened",
            "allowed_hosts": ["simulator.aegis.internal"],
            "auth_type": "NONE",
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 1. Invalid module names must be rejected with HTTP 422
    for bad_modules in (["INVALID_MODULE"], ["LLM", "NON_EXISTENT"], ["   "]):
        bad_resp = client.post(
            "/api/v1/assessments",
            headers=headers,
            json={
                "name": "Invalid Module Assessment",
                "target_profile_id": target_id,
                "selected_modules": bad_modules,
                "scope_attestation": {"authorized": True},
            },
        )
        assert bad_resp.status_code == 422
        assert bad_resp.json()["error"]["code"] == "REQUEST_VALIDATION_FAILED"

    # 2. Valid modules (including lowercase normalization and CONFIG module) succeed
    ok_resp = client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "Valid Normalized Modules Assessment",
            "target_profile_id": target_id,
            "selected_modules": ["llm", "rag", "CONFIG"],
            "scope_attestation": {"authorized": True},
        },
    )
    assert ok_resp.status_code == 201
    assert ok_resp.json()["selected_modules"] == ["LLM", "RAG", "CONFIG"]


# ---------------------------------------------------------------------------
# Task E: Concurrent Assessment Execution & Interruption Recovery Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_assessment_execution_prevented_and_interrupted_run_recovers(
    db_session: Session,
    multi_tenant_seed: dict[str, Any],
) -> None:
    """Verify two concurrent run_assessment calls cannot execute the same assessment and cancelled runs mark FAILED."""
    org_alpha = multi_tenant_seed["org_alpha"]
    alpha_engineer = multi_tenant_seed["alpha_engineer"]

    reg = SecurityTestRegistry()

    @register_security_test(registry=reg)
    class SlowAsyncPlugin(BaseSecurityTest):
        test_id = "CONC-SLOW-001"
        title = "Slow Concurrent Verification Plugin"
        category = "Concurrency Test"
        module = ScannerModule.LLM.value
        target_component = "LLM_CORE"

        async def execute(self, context: TestContext, adapter: Any) -> NormalizedTestResult:
            await asyncio.sleep(0.05)
            resp = await adapter.send_prompt("Benign concurrency check")
            return NormalizedTestResult(
                test_id=self.test_id,
                test_title=self.title,
                assessment_id=context.assessment_id,
                target_component=self.target_component,
                test_category=self.category,
                module=self.module,
                execution_status=ExecutionStatus.PASS,
                vulnerability_status=VulnerabilityStatus.SECURE,
                probes_sent=1,
                execution_log={"status": resp.status_code},
            )

    target = TargetProfile(
        organization_id=org_alpha.id,
        name="Concurrency Test Target",
        architecture_type=ArchitectureTypeEnum.LLM_APP.value,
        integration_mode=IntegrationModeEnum.SIMULATOR.value,
        endpoint_url="https://simulator.aegis.internal/hardened",
        allowed_hosts=["simulator.aegis.internal"],
        auth_type=AuthTypeEnum.NONE.value,
    )
    db_session.add(target)
    db_session.commit()

    assessment = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Concurrent Execution Guard Test",
        selected_modules=["LLM"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    db_session.add(assessment)
    db_session.commit()

    orchestrator = AssessmentOrchestrator(db_session, registry=reg)

    # 1. Launch two concurrent executions of the same assessment_id
    outcomes = await asyncio.gather(
        orchestrator.run_assessment(assessment.id),
        orchestrator.run_assessment(assessment.id),
        return_exceptions=True,
    )
    successes = [o for o in outcomes if isinstance(o, Assessment)]
    errors = [o for o in outcomes if isinstance(o, ScopeViolationError)]
    assert len(successes) == 1
    assert len(errors) == 1
    assert successes[0].status == AssessmentStatusEnum.COMPLETED.value
    assert len(successes[0].test_results) == 1

    # 2. Verify an interrupted / cancelled execution transitions cleanly to FAILED and is not stuck in EXECUTING_TESTS
    cancel_reg = SecurityTestRegistry()

    @register_security_test(registry=cancel_reg)
    class CancelledPlugin(BaseSecurityTest):
        test_id = "CANCEL-001"
        title = "Interrupted Plugin"
        category = "Interruption"
        module = ScannerModule.LLM.value
        target_component = "LLM_CORE"

        async def execute(self, context: TestContext, adapter: Any) -> NormalizedTestResult:
            raise asyncio.CancelledError("Simulated worker cancellation mid-execution")

    interrupted_asmt = Assessment(
        organization_id=org_alpha.id,
        target_profile_id=target.id,
        initiated_by_user_id=alpha_engineer.id,
        name="Interrupted Assessment Test",
        selected_modules=["LLM"],
        status=AssessmentStatusEnum.DRAFT.value,
        scope_attestation={"authorized": True},
    )
    db_session.add(interrupted_asmt)
    db_session.commit()

    cancel_orchestrator = AssessmentOrchestrator(db_session, registry=cancel_reg)
    with pytest.raises(asyncio.CancelledError):
        await cancel_orchestrator.run_assessment(interrupted_asmt.id)

    db_session.refresh(interrupted_asmt)
    assert interrupted_asmt.status == AssessmentStatusEnum.FAILED.value
    assert interrupted_asmt.completed_at is not None
    assert "CancelledError" in str(interrupted_asmt.summary_metrics.get("failure_type"))


# ---------------------------------------------------------------------------
# Task F: DNS Rebinding / TOCTOU Protection Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_target_client_pins_validated_ipv4_and_ipv6_against_dns_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate DNS rebinding between validation and connection and verify SafeTargetClient connects to the pinned IP."""
    dns_lookup_calls: list[str] = []
    observed_requests: list[httpx.Request] = []

    def _rebinding_getaddrinfo(host: str, port: int, **_kwargs: Any) -> list[Any]:
        dns_lookup_calls.append(host)
        if host == "rebind.customer.example.com":
            # First lookup returns public IP; any subsequent lookup would rebind to AWS IMDS 169.254.169.254!
            ip = "93.184.216.34" if dns_lookup_calls.count(host) == 1 else "169.254.169.254"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        if host == "ipv6.customer.example.com":
            ip6 = (
                "2606:2800:220:1:248:1893:25c8:1946"
                if dns_lookup_calls.count(host) == 1
                else "::1"
            )
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip6, port, 0, 0))]
        raise AssertionError(f"Unexpected DNS lookup for host: {host}")

    monkeypatch.setattr(socket, "getaddrinfo", _rebinding_getaddrinfo)

    def _inspecting_transport(request: httpx.Request) -> httpx.Response:
        observed_requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Pinned response"},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    # 1. IPv4 DNS Rebinding Prevention Verification
    client_v4 = SafeTargetClient(
        endpoint_url="https://rebind.customer.example.com/v1/chat/completions",
        allowed_hosts=["rebind.customer.example.com"],
        rate_limit_rps=50.0,
        transport=httpx.MockTransport(_inspecting_transport),
        resolve_dns=True,
    )
    adapter_v4 = OpenAICompatibleAdapter(client_v4)
    resp_v4 = await adapter_v4.send_prompt("Verify IPv4 pinning")
    await adapter_v4.close()

    assert resp_v4.status_code == 200
    assert resp_v4.output_text == "Pinned response"
    assert dns_lookup_calls.count("rebind.customer.example.com") == 1
    req_v4 = observed_requests[0]
    # Connection target is pinned to the validated public IPv4 address (never 169.254.169.254 or unpinned hostname)
    assert req_v4.url.host == "93.184.216.34"
    assert req_v4.url.path == "/v1/chat/completions"
    assert req_v4.headers["Host"] == "rebind.customer.example.com"
    assert req_v4.extensions["sni_hostname"] == "rebind.customer.example.com"
    assert req_v4.extensions["aegis_pinned_ip"] == "93.184.216.34"
    # Redacted evidence envelope preserves the logical target URL
    assert resp_v4.raw_request["url"] == "https://rebind.customer.example.com/v1/chat/completions"

    # 2. IPv6 DNS Rebinding Prevention & Custom Port Verification
    client_v6 = SafeTargetClient(
        endpoint_url="https://ipv6.customer.example.com:8443/v1/chat/completions",
        allowed_hosts=["ipv6.customer.example.com"],
        rate_limit_rps=50.0,
        transport=httpx.MockTransport(_inspecting_transport),
        resolve_dns=True,
    )
    adapter_v6 = OpenAICompatibleAdapter(client_v6)
    resp_v6 = await adapter_v6.send_prompt("Verify IPv6 pinning")
    await adapter_v6.close()

    assert resp_v6.status_code == 200
    assert dns_lookup_calls.count("ipv6.customer.example.com") == 1
    req_v6 = observed_requests[1]
    assert req_v6.url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert req_v6.url.port == 8443
    assert req_v6.headers["Host"] == "ipv6.customer.example.com:8443"
    assert req_v6.extensions["sni_hostname"] == "ipv6.customer.example.com"
    assert req_v6.extensions["aegis_pinned_ip"] == "2606:2800:220:1:248:1893:25c8:1946"
