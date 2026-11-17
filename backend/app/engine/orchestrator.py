"""Assessment Pipeline State Machine Orchestrator & Job Runner (`AssessmentOrchestrator`).

Implements ARCHITECTURE.md Section 4.1, 4.2, 4.3, 5 and SECURITY_DESIGN.md Section 2:
- Enforces the 8-state assessment lifecycle:
  DRAFT -> QUEUED -> PROFILING -> ANALYZING_ARCHITECTURE -> EXECUTING_TESTS -> EVALUATING -> COMPLETED / FAILED
- Enforces Gate 1 (Scope & SSRF allowlist), Gate 2 (Cryptographic Scope Attestation), and Gate 3 (Execution budgets).
- Guarantees strict separation between PASS, FAIL, ERROR (on timeout/5xx/budget), NOT_APPLICABLE, and NEEDS_REVIEW.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any

import httpx
from sqlalchemy import update
from sqlalchemy.orm import Session

import app.engine.scanners  # noqa: F401 - ensure built-in scanner plugins are registered
from app.core.audit import record_audit_event
from app.core.config import get_settings
from app.core.crypto import decrypt_credentials
from app.core.exceptions import (
    CredentialDecryptionError,
    ResourceNotFoundError,
    ScopeViolationError,
    SSRFBlockedError,
)
from app.db.base import utc_now
from app.engine.adapters import RequestBudgetExceededError, create_target_adapter
from app.engine.config_analyzer import ConfigurationAnalyzer
from app.engine.contracts import (
    ConfidenceLevel,
    ExecutionStatus,
    NormalizedTestResult,
    SeverityLevel,
    TestContext,
    VulnerabilityStatus,
)
from app.engine.evidence import EvidenceCollector, redact_string, sanitize_payload
from app.engine.framework_mapper import (
    FrameworkMappingEngine,
    ensure_knowledge_base_seeded,
)
from app.engine.profiler import TargetProfiler
from app.engine.registry import SecurityTestRegistry, default_registry
from app.engine.remediation_engine import RemediationEngine
from app.engine.risk_engine import (
    RiskAssessmentEngine,
    compute_avss_v1,  # noqa: F401
    compute_posture_grade,
)
from app.models.assessment import Assessment, AssessmentStatusEnum
from app.models.finding import Finding, TechnicalEvidence, TestExecutionResult
from app.models.target import TargetProfile

logger = logging.getLogger("aegis.engine.orchestrator")

# In-process guard preventing concurrent coroutine execution of the same assessment_id
_ACTIVE_ASSESSMENT_RUNS: set[str] = set()

# Valid state machine transitions
VALID_STATE_TRANSITIONS: dict[str, set[str]] = {
    AssessmentStatusEnum.DRAFT.value: {
        AssessmentStatusEnum.QUEUED.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.QUEUED.value: {
        AssessmentStatusEnum.PROFILING.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.PROFILING.value: {
        AssessmentStatusEnum.ANALYZING_ARCHITECTURE.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.ANALYZING_ARCHITECTURE.value: {
        AssessmentStatusEnum.EXECUTING_TESTS.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.EXECUTING_TESTS.value: {
        AssessmentStatusEnum.EVALUATING.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.EVALUATING.value: {
        AssessmentStatusEnum.COMPLETED.value,
        AssessmentStatusEnum.FAILED.value,
    },
    AssessmentStatusEnum.COMPLETED.value: set(),
    AssessmentStatusEnum.FAILED.value: set(),
}


class AssessmentOrchestrator:
    """Executes and coordinates an AegisAI security assessment across its full lifecycle."""

    def __init__(
        self,
        db: Session,
        *,
        registry: SecurityTestRegistry | None = None,
        profiler: TargetProfiler | None = None,
        config_analyzer: ConfigurationAnalyzer | None = None,
        risk_engine: RiskAssessmentEngine | None = None,
        remediation_engine: RemediationEngine | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        resolve_dns: bool | None = None,
        max_assessment_duration_seconds: float = 300.0,
    ) -> None:
        self.db = db
        self.registry = registry or default_registry
        self.profiler = profiler or TargetProfiler()
        self.config_analyzer = config_analyzer or ConfigurationAnalyzer()
        self.risk_engine = risk_engine or RiskAssessmentEngine()
        self.remediation_engine = remediation_engine or RemediationEngine()
        self.transport = transport
        self.resolve_dns = resolve_dns
        self.max_assessment_duration_seconds = max_assessment_duration_seconds

    def _transition_state(
        self,
        assessment: Assessment,
        new_status: AssessmentStatusEnum,
        *,
        progress_pct: int | None = None,
    ) -> None:
        """Validate and persist a state machine transition on `assessment`."""
        current = assessment.status
        if current == new_status.value:
            if progress_pct is not None:
                assessment.progress_pct = progress_pct
                self.db.commit()
            return

        allowed = VALID_STATE_TRANSITIONS.get(current, set())
        if new_status.value not in allowed:
            raise ScopeViolationError(
                f"Invalid assessment state transition from '{current}' to '{new_status.value}'."
            )

        assessment.status = new_status.value
        if progress_pct is not None:
            assessment.progress_pct = progress_pct
        self.db.commit()
        self.db.refresh(assessment)

    def attest_and_queue_assessment(
        self,
        assessment: Assessment,
        target: TargetProfile,
        *,
        attested_by_user_id: str,
        client_ip: str = "127.0.0.1",
    ) -> Assessment:
        """Enforce Gate 2 (Cryptographic Scope Attestation), snapshot TargetProfile, and transition to QUEUED."""
        attestation = dict(assessment.scope_attestation or {})
        if not attestation.get("authorized", False):
            raise ScopeViolationError(
                "Explicit scope authorization ('authorized': true) is required before queuing an assessment."
            )

        # Compute deterministic SHA-256 scope attestation digest
        scope_canonical = json.dumps(
            {
                "organization_id": assessment.organization_id,
                "target_id": target.id,
                "endpoint_url": target.endpoint_url,
                "allowed_hosts": sorted(target.allowed_hosts),
                "selected_modules": sorted(assessment.selected_modules),
                "attested_by_user_id": attested_by_user_id,
            },
            sort_keys=True,
        )
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()
        attestation["scope_attestation_hash"] = scope_hash
        attestation["attested_by_user_id"] = attested_by_user_id
        attestation["attested_at"] = utc_now().isoformat()
        attestation["client_ip"] = client_ip
        assessment.scope_attestation = attestation

        # Capture immutable non-secret snapshot of TargetProfile (DATABASE_SCHEMA.md Section 4.2)
        assessment.target_profile_snapshot = {
            "id": target.id,
            "name": target.name,
            "architecture_type": target.architecture_type,
            "integration_mode": target.integration_mode,
            "endpoint_url": target.endpoint_url,
            "allowed_hosts": list(target.allowed_hosts),
            "auth_type": target.auth_type,
            "credential_preview": target.credential_preview,
            "request_template": dict(target.request_template or {}),
            "architecture_manifest": dict(target.architecture_manifest or {}),
            "rag_harness_config": dict(target.rag_harness_config or {})
            if target.rag_harness_config
            else None,
            "agent_harness_config": dict(target.agent_harness_config or {})
            if target.agent_harness_config
            else None,
            "rate_limit_rps": target.rate_limit_rps,
            "timeout_seconds": target.timeout_seconds,
        }

        if assessment.status == AssessmentStatusEnum.DRAFT.value:
            self._transition_state(
                assessment, AssessmentStatusEnum.QUEUED, progress_pct=5
            )

        record_audit_event(
            self.db,
            organization_id=assessment.organization_id,
            user_id=attested_by_user_id,
            action="ASSESSMENT_SCOPE_ATTESTED",
            resource_type="ASSESSMENT",
            resource_id=assessment.id,
            details={
                "target_id": target.id,
                "endpoint_url": target.endpoint_url,
                "allowed_hosts": target.allowed_hosts,
                "scope_attestation_hash": scope_hash,
                "client_ip": client_ip,
            },
        )
        return assessment

    async def run_assessment(self, assessment_id: str) -> Assessment:
        """Execute the full assessment pipeline from QUEUED (or DRAFT if attested) to COMPLETED/FAILED."""
        assessment = (
            self.db.query(Assessment).filter(Assessment.id == assessment_id).first()
        )
        if not assessment:
            raise ResourceNotFoundError("Assessment", assessment_id)

        target = (
            self.db.query(TargetProfile)
            .filter(
                TargetProfile.id == assessment.target_profile_id,
                TargetProfile.organization_id == assessment.organization_id,
            )
            .first()
        )
        if not target:
            raise ResourceNotFoundError("TargetProfile", assessment.target_profile_id)

        if assessment_id in _ACTIVE_ASSESSMENT_RUNS:
            raise ScopeViolationError(
                f"Assessment '{assessment_id}' is already executing concurrently."
            )

        if assessment.status not in (
            AssessmentStatusEnum.DRAFT.value,
            AssessmentStatusEnum.QUEUED.value,
        ):
            raise ScopeViolationError(
                f"Cannot execute assessment in state '{assessment.status}'; must be DRAFT or QUEUED."
            )

        _ACTIVE_ASSESSMENT_RUNS.add(assessment_id)
        adapter = None
        claimed_execution = False
        wall_clock_start = time.monotonic()

        try:
            # Ensure assessment is attested and in QUEUED state
            if assessment.status == AssessmentStatusEnum.DRAFT.value:
                claimed_execution = True
                self.attest_and_queue_assessment(
                    assessment,
                    target,
                    attested_by_user_id=assessment.initiated_by_user_id,
                )

            # 1. Atomic database claim transition: QUEUED -> PROFILING
            claimed_execution = False
            started_ts = utc_now()
            claim_stmt = (
                update(Assessment)
                .where(
                    Assessment.id == assessment.id,
                    Assessment.status == AssessmentStatusEnum.QUEUED.value,
                )
                .values(
                    status=AssessmentStatusEnum.PROFILING.value,
                    progress_pct=15,
                    started_at=started_ts,
                )
            )
            claim_res = self.db.execute(claim_stmt)
            self.db.commit()
            if (claim_res.rowcount or 0) != 1:
                self.db.refresh(assessment)
                raise ScopeViolationError(
                    f"Cannot execute assessment in state '{assessment.status}'; already claimed or not QUEUED."
                )
            claimed_execution = True
            self.db.refresh(assessment)

            # Decrypt credentials in memory only
            decrypted_creds: dict[str, Any] = {}
            if target.encrypted_credentials:
                decrypted_creds = decrypt_credentials(
                    target.encrypted_credentials,
                    organization_id=assessment.organization_id,
                )

            settings = get_settings()
            should_resolve_dns = (
                self.resolve_dns
                if self.resolve_dns is not None
                else (target.integration_mode not in ("SIMULATOR", "CONFIG_ONLY"))
            )

            adapter = create_target_adapter(
                integration_mode=target.integration_mode,
                endpoint_url=target.endpoint_url,
                allowed_hosts=target.allowed_hosts,
                auth_type=target.auth_type,
                decrypted_credentials=decrypted_creds,
                request_template=target.request_template,
                architecture_manifest=target.architecture_manifest,
                rag_harness_config=target.rag_harness_config,
                agent_harness_config=target.agent_harness_config,
                rate_limit_rps=target.rate_limit_rps,
                timeout_seconds=target.timeout_seconds,
                max_total_requests=settings.aegis_max_requests_per_assessment,
                transport=self.transport,
                resolve_dns=should_resolve_dns,
            )

            record_audit_event(
                self.db,
                organization_id=assessment.organization_id,
                user_id=assessment.initiated_by_user_id,
                action="SCAN_STARTED",
                resource_type="ASSESSMENT",
                resource_id=assessment.id,
                details={
                    "target_id": target.id,
                    "selected_modules": assessment.selected_modules,
                },
            )

            profile_result = await self.profiler.profile_target(
                endpoint_url=target.endpoint_url,
                allowed_hosts=target.allowed_hosts,
                integration_mode=target.integration_mode,
                adapter=adapter,
                resolve_dns=should_resolve_dns,
            )

            if profile_result.error_reason:
                if "SCOPE_AUTHORIZATION_VIOLATION" in profile_result.error_reason:
                    raise ScopeViolationError(profile_result.error_reason)
                if "SSRF_BOUNDARY_BLOCKED" in profile_result.error_reason:
                    raise SSRFBlockedError(profile_result.error_reason)

            # 2. ANALYZING_ARCHITECTURE State
            self._transition_state(
                assessment,
                AssessmentStatusEnum.ANALYZING_ARCHITECTURE,
                progress_pct=25,
            )
            arch_analysis = self.config_analyzer.analyze(
                architecture_type=target.architecture_type,
                architecture_manifest=target.architecture_manifest,
                rag_harness_config=target.rag_harness_config,
                agent_harness_config=target.agent_harness_config,
            )

            # 3. EXECUTING_TESTS State
            self._transition_state(
                assessment, AssessmentStatusEnum.EXECUTING_TESTS, progress_pct=35
            )

            planned_plugins = self.registry.get_tests_for_assessment(
                selected_modules=assessment.selected_modules,
                architecture_type=target.architecture_type,
                include_non_applicable=True,
            )
            if not planned_plugins:
                raise ScopeViolationError(
                    f"No security tests matched selected_modules={assessment.selected_modules}. "
                    "Assessment cannot execute with zero planned tests."
                )
            assessment.total_tests_planned = len(planned_plugins)
            assessment.tests_completed = 0
            self.db.commit()

            mutating_confirmed = bool(
                (assessment.scope_attestation or {}).get("agent_sandbox_confirmed")
                or (assessment.scope_attestation or {}).get("dry_run_confirmed")
                or (target.agent_harness_config or {}).get("dry_run", False)
                or target.integration_mode in ("SIMULATOR", "CONFIG_ONLY")
            )

            context = TestContext(
                assessment_id=assessment.id,
                organization_id=assessment.organization_id,
                target_id=target.id,
                target_name=target.name,
                architecture_type=target.architecture_type,
                integration_mode=target.integration_mode,
                endpoint_url=target.endpoint_url,
                allowed_hosts=list(target.allowed_hosts),
                request_template=dict(target.request_template or {}),
                architecture_manifest=dict(target.architecture_manifest or {}),
                rag_harness_config=target.rag_harness_config,
                agent_harness_config=target.agent_harness_config,
                scope_attestation=dict(assessment.scope_attestation or {}),
                profile_result=profile_result,
                architecture_analysis=arch_analysis,
                mutating_confirmed=mutating_confirmed,
            )

            executed_pairs: list[tuple[NormalizedTestResult, TestExecutionResult]] = []

            for idx, plugin in enumerate(planned_plugins):
                # Enforce wall-clock assessment duration ceiling (Gate 3)
                elapsed_wall = time.monotonic() - wall_clock_start
                if elapsed_wall > self.max_assessment_duration_seconds:
                    norm_result = self._build_error_result(
                        plugin=plugin,
                        assessment_id=assessment.id,
                        reason=f"Assessment wall-clock duration budget ({self.max_assessment_duration_seconds}s) exceeded.",
                        error_code="ASSESSMENT_DURATION_EXCEEDED",
                    )
                else:
                    norm_result = await self._execute_single_plugin(
                        plugin=plugin,
                        context=context,
                        adapter=adapter,
                        per_test_timeout=float(target.timeout_seconds * 4),
                    )

                # Sanitize all technical evidence items and logs prior to persistence
                sanitized_evidence = [
                    EvidenceCollector.sanitize_evidence_item(item)
                    for item in norm_result.technical_evidence
                ]
                sanitized_log = sanitize_payload(norm_result.execution_log)
                if not isinstance(sanitized_log, dict):
                    sanitized_log = {"log": sanitized_log}
                norm_result = norm_result.model_copy(
                    update={
                        "technical_evidence": sanitized_evidence,
                        "execution_log": sanitized_log,
                        "description": redact_string(norm_result.description),
                        "risk_rationale": redact_string(norm_result.risk_rationale),
                        "exploitability_summary": redact_string(norm_result.exploitability_summary),
                    }
                )

                db_test_result = TestExecutionResult(
                    assessment_id=assessment.id,
                    test_id=norm_result.test_id,
                    module=norm_result.module,
                    test_title=norm_result.test_title or plugin.title or norm_result.test_id,
                    test_category=norm_result.test_category or plugin.category,
                    target_component=norm_result.target_component or plugin.target_component,
                    execution_status=norm_result.execution_status.value,
                    vulnerability_status=norm_result.vulnerability_status.value,
                    probes_sent=norm_result.probes_sent,
                    execution_duration_ms=round(norm_result.execution_duration_ms, 2),
                    execution_log=sanitized_log,
                )
                self.db.add(db_test_result)
                self.db.flush()
                executed_pairs.append((norm_result, db_test_result))

                assessment.tests_completed = idx + 1
                if planned_plugins:
                    ratio = (idx + 1) / len(planned_plugins)
                    assessment.progress_pct = 35 + int(ratio * 45)
                self.db.commit()

            # 4. EVALUATING State
            self._transition_state(
                assessment, AssessmentStatusEnum.EVALUATING, progress_pct=85
            )
            seeded_frameworks = ensure_knowledge_base_seeded(self.db)
            framework_mapper = FrameworkMappingEngine(self.db)

            status_counts: dict[str, int] = {
                ExecutionStatus.PASS.value: 0,
                ExecutionStatus.FAIL.value: 0,
                ExecutionStatus.ERROR.value: 0,
                ExecutionStatus.NOT_APPLICABLE.value: 0,
                ExecutionStatus.NEEDS_REVIEW.value: 0,
            }
            severity_counts: dict[str, int] = {
                SeverityLevel.CRITICAL.value: 0,
                SeverityLevel.HIGH.value: 0,
                SeverityLevel.MEDIUM.value: 0,
                SeverityLevel.LOW.value: 0,
                SeverityLevel.INFORMATIONAL.value: 0,
            }
            finding_scores: list[float] = []

            for norm_result, db_test_result in executed_pairs:
                st_key = norm_result.execution_status.value
                status_counts[st_key] = status_counts.get(st_key, 0) + 1

                if norm_result.execution_status in (
                    ExecutionStatus.FAIL,
                    ExecutionStatus.NEEDS_REVIEW,
                ):
                    finding = self._persist_finding_and_evidence(
                        assessment=assessment,
                        norm_result=norm_result,
                        db_test_result=db_test_result,
                        architecture_type=target.architecture_type,
                        compensating_multiplier=arch_analysis.compensating_multiplier,
                        compensating_controls=arch_analysis.compensating_controls,
                        framework_mapper=framework_mapper,
                    )
                    sev_key = finding.severity
                    severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1
                    finding_scores.append(finding.avss_score)

            overall_risk = round(max(finding_scores) if finding_scores else 0.0, 1)
            posture_grade = compute_posture_grade(overall_risk, severity_counts)

            assessment.overall_risk_score = overall_risk
            assessment.posture_grade = posture_grade
            assessment.summary_metrics = {
                "status_counts": status_counts,
                "severity_counts": severity_counts,
                "total_findings": len(finding_scores),
                "total_probes_sent": adapter.total_probes_sent if adapter else 0,
                "profile": profile_result.model_dump(),
                "architecture_analysis": arch_analysis.summary,
                "framework_kb_snapshot": {
                    fw.id: {
                        "id": fw.id,
                        "name": fw.name,
                        "version": fw.version,
                        "publisher": fw.publisher,
                        "release_date": fw.release_date,
                        "official_url": fw.official_url,
                        "description": fw.description,
                    }
                    for fw in (
                        seeded_frameworks.values()
                        if isinstance(seeded_frameworks, dict)
                        else seeded_frameworks
                    )
                },
            }

            # 5. COMPLETED State
            assessment.completed_at = utc_now()
            self._transition_state(
                assessment, AssessmentStatusEnum.COMPLETED, progress_pct=100
            )

            record_audit_event(
                self.db,
                organization_id=assessment.organization_id,
                user_id=assessment.initiated_by_user_id,
                action="ASSESSMENT_COMPLETED",
                resource_type="ASSESSMENT",
                resource_id=assessment.id,
                details={
                    "overall_risk_score": overall_risk,
                    "posture_grade": posture_grade,
                    "status_counts": status_counts,
                    "severity_counts": severity_counts,
                },
            )
            return assessment

        except BaseException as exc:
            if not claimed_execution:
                raise
            logger.error(
                "Assessment '%s' failed or was interrupted during orchestration: %s",
                assessment.id,
                exc,
            )
            try:
                self.db.rollback()
            except Exception:
                pass
            assessment = (
                self.db.query(Assessment).filter(Assessment.id == assessment_id).first()
                or assessment
            )
            assessment.completed_at = utc_now()
            assessment.summary_metrics = {
                **(assessment.summary_metrics or {}),
                "failure_reason": str(exc) or exc.__class__.__name__,
                "failure_type": exc.__class__.__name__,
            }
            if assessment.status != AssessmentStatusEnum.FAILED.value:
                assessment.status = AssessmentStatusEnum.FAILED.value
            self.db.commit()
            self.db.refresh(assessment)

            record_audit_event(
                self.db,
                organization_id=assessment.organization_id,
                user_id=assessment.initiated_by_user_id,
                action="ASSESSMENT_FAILED",
                resource_type="ASSESSMENT",
                resource_id=assessment.id,
                details={
                    "failure_type": exc.__class__.__name__,
                    "failure_reason": str(exc) or exc.__class__.__name__,
                },
            )
            if isinstance(
                exc, (SSRFBlockedError, ScopeViolationError, CredentialDecryptionError)
            ) or not isinstance(exc, Exception):
                raise
            return assessment
        finally:
            _ACTIVE_ASSESSMENT_RUNS.discard(assessment_id)
            if adapter is not None:
                await adapter.close()

    async def _execute_single_plugin(
        self,
        *,
        plugin: Any,
        context: TestContext,
        adapter: Any,
        per_test_timeout: float,
    ) -> NormalizedTestResult:
        """Execute a single BaseSecurityTest plugin with applicability and timeout/error isolation."""
        applicable, reason = plugin.is_applicable(context)
        if not applicable:
            return NormalizedTestResult(
                test_id=plugin.test_id,
                test_title=plugin.title,
                assessment_id=context.assessment_id,
                target_component=plugin.target_component,
                test_category=plugin.category,
                module=plugin.module,
                execution_status=ExecutionStatus.NOT_APPLICABLE,
                vulnerability_status=VulnerabilityStatus.UNDETERMINED,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=ConfidenceLevel.HIGH,
                risk_score=0.0,
                risk_rationale=reason,
                description=plugin.description or reason,
                probes_sent=0,
                execution_duration_ms=0.0,
                execution_log={"applicability_note": reason},
            )

        probes_before = adapter.total_probes_sent if adapter else 0
        t0 = time.perf_counter()
        try:
            result: NormalizedTestResult = await asyncio.wait_for(
                plugin.execute(context, adapter),
                timeout=max(5.0, per_test_timeout),
            )
            duration_ms = (time.perf_counter() - t0) * 1000.0
            probes_delta = max(
                result.probes_sent,
                (adapter.total_probes_sent if adapter else 0) - probes_before,
            )
            return result.model_copy(
                update={
                    "test_title": result.test_title or plugin.title or plugin.test_id,
                    "execution_duration_ms": round(
                        result.execution_duration_ms or duration_ms, 2
                    ),
                    "probes_sent": probes_delta,
                }
            )
        except TimeoutError:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_error_result(
                plugin=plugin,
                assessment_id=context.assessment_id,
                reason=f"Plugin '{plugin.test_id}' timed out after {per_test_timeout}s.",
                error_code="PLUGIN_TIMEOUT",
                duration_ms=duration_ms,
                probes_sent=(adapter.total_probes_sent if adapter else 0) - probes_before,
            )
        except RequestBudgetExceededError as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_error_result(
                plugin=plugin,
                assessment_id=context.assessment_id,
                reason=str(exc),
                error_code="REQUEST_BUDGET_EXCEEDED",
                duration_ms=duration_ms,
                probes_sent=(adapter.total_probes_sent if adapter else 0) - probes_before,
            )
        except (SSRFBlockedError, ScopeViolationError):
            raise
        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return self._build_error_result(
                plugin=plugin,
                assessment_id=context.assessment_id,
                reason=f"Plugin '{plugin.test_id}' raised unexpected error: {exc}",
                error_code="PLUGIN_EXECUTION_ERROR",
                duration_ms=duration_ms,
                probes_sent=(adapter.total_probes_sent if adapter else 0) - probes_before,
            )

    @staticmethod
    def _build_error_result(
        *,
        plugin: Any,
        assessment_id: str,
        reason: str,
        error_code: str,
        duration_ms: float = 0.0,
        probes_sent: int = 0,
    ) -> NormalizedTestResult:
        """Build an explicit ExecutionStatus.ERROR result (never treating errors/timeouts as PASS)."""
        return NormalizedTestResult(
            test_id=plugin.test_id,
            test_title=plugin.title,
            assessment_id=assessment_id,
            target_component=plugin.target_component,
            test_category=plugin.category,
            module=plugin.module,
            execution_status=ExecutionStatus.ERROR,
            vulnerability_status=VulnerabilityStatus.UNDETERMINED,
            severity=SeverityLevel.INFORMATIONAL,
            confidence=ConfidenceLevel.LOW,
            risk_score=0.0,
            risk_rationale=f"Test could not determine vulnerability status due to execution error: {reason}",
            description=plugin.description or plugin.title,
            probes_sent=max(0, probes_sent),
            execution_duration_ms=round(duration_ms, 2),
            execution_log={
                "error_code": error_code,
                "error_message": reason,
            },
        )

    def _persist_finding_and_evidence(
        self,
        *,
        assessment: Assessment,
        norm_result: NormalizedTestResult,
        db_test_result: TestExecutionResult,
        architecture_type: str,
        compensating_multiplier: float,
        compensating_controls: list[str] | None = None,
        framework_mapper: FrameworkMappingEngine | None = None,
    ) -> Finding:
        """Create Finding, TechnicalEvidence, and evidence-driven FindingFrameworkMapping records."""
        risk_eval = self.risk_engine.evaluate_finding_risk(
            norm_result,
            compensating_multiplier=compensating_multiplier,
            compensating_controls=compensating_controls,
        )

        mapper = framework_mapper or FrameworkMappingEngine(self.db)
        resolved_mappings = mapper.resolve_mappings_for_result(
            norm_result,
            architecture_type=architecture_type,
        )

        remediation_dict = self.remediation_engine.build_remediation(
            norm_result,
            effective_severity=risk_eval.severity,
            resolved_mappings=resolved_mappings,
        )

        finding = Finding(
            organization_id=assessment.organization_id,
            assessment_id=assessment.id,
            test_result_id=db_test_result.id,
            test_id=norm_result.test_id,
            title=norm_result.test_title or f"{norm_result.test_id}: {norm_result.test_category}",
            module=norm_result.module,
            category=norm_result.test_category,
            affected_component=norm_result.target_component,
            severity=risk_eval.severity.value,
            confidence=risk_eval.confidence.value,
            is_confirmed=risk_eval.is_confirmed,
            avss_score=risk_eval.avss_score,
            avss_vector=risk_eval.avss_vector,
            severity_rationale=risk_eval.severity_rationale,
            description=norm_result.description
            or f"Security test {norm_result.test_id} identified a {norm_result.vulnerability_status.value} condition.",
            exploitability_summary=norm_result.exploitability_summary
            or "Exploitable via crafted prompt or API payload against the target component.",
            remediation_structured=remediation_dict,
        )
        self.db.add(finding)
        self.db.flush()

        for ev in norm_result.technical_evidence:
            req_dict = (
                ev.request_payload_redacted
                if isinstance(ev.request_payload_redacted, dict)
                else {"payload": str(ev.request_payload_redacted)}
            )
            resp_dict = (
                ev.response_body_redacted
                if isinstance(ev.response_body_redacted, dict)
                else {"body": str(ev.response_body_redacted)}
            )
            db_ev = TechnicalEvidence(
                finding_id=finding.id,
                probe_name=ev.probe_name,
                request_payload=req_dict,
                response_payload=resp_dict,
                http_status=ev.http_status_code,
                latency_ms=ev.latency_ms,
                detector_name=ev.detector_type,
                matched_artifacts=list(ev.matched_indicators),
            )
            self.db.add(db_ev)

        mapper.persist_finding_mappings(
            finding_id=finding.id,
            resolved_mappings=resolved_mappings,
        )

        self.db.flush()
        return finding
