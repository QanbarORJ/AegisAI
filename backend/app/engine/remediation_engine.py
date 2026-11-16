"""8-Part Actionable Technical Remediation Engine (`RemediationEngine`).

Implements ROADMAP.md Phase 6 and Requirements 2 & 4:
1. Grounded in `backend/app/knowledge_base/remediation_playbooks.json` and dynamically tailored
   to the specific detected vulnerability, affected component, detector types, and matched indicators.
2. Produces an 8-part structured remediation guide:
   - `summary`: Concise technical remediation objective
   - `root_cause`: Component- and evidence-specific root cause analysis
   - `priority`: Action priority aligned with technical severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
   - `preventive_controls`: Concrete engineering controls that prevent exploitation
   - `detective_controls`: Telemetry, logging, and alerting controls that detect attempted attacks
   - `implementation_steps`: Actionable, step-by-step engineering tasks tailored to observed weaknesses
   - `secure_code_example`: Reference production-grade Python/FastAPI/Schema implementation pattern
   - `verification_procedures`: Deterministic re-testing and verification steps to confirm remediation
3. Embeds an immutable `framework_mappings_snapshot` so historical assessments retain their exact
   original framework references and versions even after knowledge base updates.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.engine.contracts import (
    ExecutionStatus,
    NormalizedTestResult,
    SeverityLevel,
)
from app.engine.evidence import redact_string, sanitize_payload
from app.engine.framework_mapper import ResolvedFrameworkMapping

PLAYBOOKS_FILE = (
    Path(__file__).resolve().parents[1]
    / "knowledge_base"
    / "remediation_playbooks.json"
)


class PlaybookTemplateSchema(BaseModel):
    """Validated schema for a single remediation playbook entry."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=10)
    root_cause: str = Field(min_length=10)
    priority: str = Field(min_length=3)
    preventive_controls: list[str] = Field(min_length=1)
    detective_controls: list[str] = Field(min_length=1)
    implementation_steps: list[str] = Field(min_length=1)
    secure_code_example: str = Field(min_length=10)
    verification_procedures: list[str] = Field(min_length=1)


class PlaybookCatalogSchema(BaseModel):
    """Complete validated playbook catalog loaded from `remediation_playbooks.json`."""

    model_config = ConfigDict(extra="forbid")

    version: str
    playbooks: dict[str, PlaybookTemplateSchema]
    default_playbook: PlaybookTemplateSchema


class StructuredRemediationGuidance(BaseModel):
    """8-part structured technical remediation guidance persisted on `Finding.remediation_structured`."""

    model_config = ConfigDict(extra="allow")

    summary: str
    root_cause: str
    priority: str
    preventive_controls: list[str]
    detective_controls: list[str]
    implementation_steps: list[str]
    secure_code_example: str
    verification_procedures: list[str]
    affected_component: str
    playbook_version: str
    detected_evidence_summary: list[str] = Field(default_factory=list)
    framework_mappings_snapshot: list[dict[str, Any]] = Field(default_factory=list)


@lru_cache(maxsize=1)
def load_remediation_playbooks() -> PlaybookCatalogSchema:
    """Load and schema-validate the authoritative remediation playbooks from disk."""
    raw = json.loads(PLAYBOOKS_FILE.read_text(encoding="utf-8"))
    return PlaybookCatalogSchema.model_validate(raw)


class RemediationEngine:
    """Constructs vulnerability-specific, evidence-tailored 8-part remediation guidance."""

    def __init__(self) -> None:
        self.catalog = load_remediation_playbooks()

    def _select_base_playbook(
        self, norm_result: NormalizedTestResult
    ) -> PlaybookTemplateSchema:
        """Select playbook by `test_id`, falling back to component/category match or default playbook."""
        test_id = norm_result.test_id.upper()
        if test_id in self.catalog.playbooks:
            return self.catalog.playbooks[test_id]

        comp = (norm_result.target_component or "").upper()
        cat = (norm_result.test_category or "").upper()

        if "INDIRECT" in cat and "RAG" in cat:
            return self.catalog.playbooks["RAG-IPI-001"]
        if "INDIRECT" in cat:
            return self.catalog.playbooks["LLM-PI-002"]
        if "INJECTION" in cat or comp == "LLM_SYSTEM_PROMPT_BOUNDARY":
            return self.catalog.playbooks["LLM-PI-001"]
        if "SYSTEM PROMPT" in cat:
            return self.catalog.playbooks["LLM-SPE-001"]
        if "SENSITIVE" in cat or comp == "LLM_OUTPUT_DLP_FILTER":
            return self.catalog.playbooks["LLM-SID-001"]
        if "OUTPUT" in cat or comp == "LLM_OUTPUT_SINK":
            return self.catalog.playbooks["LLM-IOH-001"]
        if "CONSUMPTION" in cat or comp == "LLM_MODEL_CONFIG":
            return self.catalog.playbooks["LLM-CFG-001"]
        if "CROSS-TENANT" in cat or comp == "RAG_TENANT_ACL_FILTER":
            return self.catalog.playbooks["RAG-AUTH-001"]
        if "METADATA" in cat or comp == "RAG_METADATA_FILTER":
            return self.catalog.playbooks["RAG-META-001"]
        if "RAG" in comp:
            return self.catalog.playbooks["RAG-ARCH-001"]
        if "TOOL" in comp or "TOOL MISUSE" in cat:
            return self.catalog.playbooks["AGT-TOOL-001"]
        if "GOAL" in comp or "GOAL HIJACKING" in cat:
            return self.catalog.playbooks["AGT-GH-001"]
        if "HITL" in comp or "AGENT" in comp:
            return self.catalog.playbooks["AGT-PERM-001"]

        return self.catalog.default_playbook

    def build_remediation(
        self,
        norm_result: NormalizedTestResult,
        *,
        effective_severity: SeverityLevel | None = None,
        resolved_mappings: list[ResolvedFrameworkMapping] | None = None,
    ) -> dict[str, Any]:
        """Generate a sanitized, evidence-specific 8-part remediation dictionary for `norm_result`."""
        base = self._select_base_playbook(norm_result)
        plugin_rem = norm_result.recommended_remediation or {}

        sev = effective_severity or norm_result.severity
        priority = (
            sev.value
            if sev in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW)
            else str(plugin_rem.get("priority") or base.priority)
        )

        # Extract concrete evidence signals to tailor root cause, implementation steps, and verification
        detectors: list[str] = []
        probes: list[str] = []
        indicators: list[str] = []
        evidence_summaries: list[str] = []

        for ev in norm_result.technical_evidence:
            if ev.detector_type and ev.detector_type not in detectors:
                detectors.append(ev.detector_type)
            if ev.probe_name and ev.probe_name not in probes:
                probes.append(ev.probe_name)
            for ind in ev.matched_indicators:
                clean_ind = redact_string(str(ind))
                if clean_ind and clean_ind not in indicators:
                    indicators.append(clean_ind)
            if ev.matched_indicators:
                evidence_summaries.append(
                    f"Probe '{ev.probe_name}' ({ev.detector_type}) -> "
                    f"{'; '.join(redact_string(str(x)) for x in ev.matched_indicators[:2])}"
                )

        ind_blob = " | ".join(indicators).lower()

        # 1. Summary & Root Cause tailored with component and observed evidence
        summary = str(plugin_rem.get("summary") or base.summary).strip()
        base_root_cause = str(plugin_rem.get("root_cause") or base.root_cause).strip()
        if detectors or probes:
            det_str = ", ".join(detectors) if detectors else "DETERMINISTIC_EVALUATOR"
            probe_str = ", ".join(probes[:3])
            root_cause = (
                f"{base_root_cause} Component '{norm_result.target_component}' triggered "
                f"detector(s) [{det_str}] during probe(s) [{probe_str}]."
            )
        else:
            root_cause = f"{base_root_cause} (Affected component: '{norm_result.target_component}')."

        # 2. Preventive, Detective, Implementation Steps & Verification Procedures
        preventive_controls = list(
            plugin_rem.get("preventive_controls") or base.preventive_controls
        )
        detective_controls = list(
            plugin_rem.get("detective_controls") or base.detective_controls
        )
        implementation_steps = list(
            plugin_rem.get("implementation_steps") or base.implementation_steps
        )
        verification_procedures = list(
            plugin_rem.get("verification_procedures") or base.verification_procedures
        )
        secure_code_example = str(
            plugin_rem.get("secure_code_example") or base.secure_code_example
        )

        # Conditional evidence-driven tailoring of implementation & verification steps
        if "cfg-spe-001" in ind_blob:
            implementation_steps.insert(
                0,
                "URGENT (CFG-SPE-001): Immediately revoke, rotate, and purge the hardcoded credential/PII detected inside 'architecture_manifest.system_prompt'.",
            )
        if "markdown image beacon" in ind_blob:
            verification_procedures.append(
                "Verify that rendered Markdown outputs strip or block external `![alt](https://...)` image beacon URLs."
            )
        if "sql sink payload" in ind_blob:
            verification_procedures.append(
                "Verify that downstream database queries reject unparameterized SQL tautologies (`OR '1'='1'`)."
            )
        if "cfg-rag-001" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-RAG-001: Set `enforce_tenant_filter: true` in `rag_harness_config` / vector store adapter."
            )
        if "cfg-rag-002" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-RAG-002: Reduce `chunk_size` in `rag_harness_config` to <= 2048 tokens (recommended 512 tokens)."
            )
        if "cfg-rag-003" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-RAG-003: Enable `sanitize_ingested_documents: true` on the RAG ingestion pipeline."
            )
        if "cfg-agt-001" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-AGT-001: Set `human_in_the_loop: true` in `agent_harness_config` for all privileged tool calls."
            )
            verification_procedures.append(
                "Verification for CFG-AGT-001: Confirm `agent_harness_config['human_in_the_loop']` is `True` and privileged tool calls return `pending_approval`."
            )
        if "cfg-agt-002" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-AGT-002: Set `max_iterations` <= 25 (recommended 10) in `agent_harness_config`."
            )
            verification_procedures.append(
                "Verification for CFG-AGT-002: Confirm `agent_harness_config['max_iterations']` is <= 25."
            )
        if "cfg-agt-003" in ind_blob:
            implementation_steps.append(
                "Remediation for CFG-AGT-003: Set `additionalProperties: false` on all registered tool parameter JSON schemas."
            )
            verification_procedures.append(
                "Verification for CFG-AGT-003: Confirm every tool schema in `agent_harness_config['tools']` sets `additionalProperties: false`."
            )

        if norm_result.execution_status == ExecutionStatus.NEEDS_REVIEW:
            verification_procedures.insert(
                0,
                "Analyst Triage Step (NEEDS_REVIEW / Low Confidence): Inspect the captured request/response evidence trace to confirm whether the ambiguous behavioral indicator represents a partial policy bypass or a benign refusal.",
            )

        snapshot = [
            m.model_dump(mode="json") for m in (resolved_mappings or [])
        ]

        guidance = StructuredRemediationGuidance(
            summary=redact_string(summary),
            root_cause=redact_string(root_cause),
            priority=priority,
            preventive_controls=[redact_string(c) for c in preventive_controls],
            detective_controls=[redact_string(c) for c in detective_controls],
            implementation_steps=[redact_string(s) for s in implementation_steps],
            secure_code_example=redact_string(secure_code_example),
            verification_procedures=[redact_string(v) for v in verification_procedures],
            affected_component=norm_result.target_component,
            playbook_version=self.catalog.version,
            detected_evidence_summary=evidence_summaries,
            framework_mappings_snapshot=snapshot,
        )
        sanitized = sanitize_payload(guidance.model_dump())
        return sanitized if isinstance(sanitized, dict) else guidance.model_dump()
