"""Authoritative Security Framework Knowledge Base Loader, Immutable Seeder & Evidence-Driven Mapping Engine.

Implements ROADMAP.md Phase 6 and Requirements 1 & 4:
1. Authoritative JSON Knowledge Base covering OWASP LLM Top 10 (2026), OWASP Agentic Top 10 (2026),
   OWASP AISVS v1.0, NIST AI RMF 1.0 & AI 600-1, MITRE ATLAS, and ISO/IEC 42001:2023 & 23894:2023.
2. Immutable Framework Versioning: Once a framework version is seeded, its definition and controls
   cannot be destructively overwritten. Historical assessments retain their exact original framework
   references and version metadata even after new framework versions are added to the knowledge base.
3. Evidence-Driven Conditional Mapping Engine: Distinguishes DIRECT, RELATED, and SUPPORTING
   relationships using conditional applicability rules over technical evidence (detector types,
   matched indicators, static config rules, target component, and architecture) rather than relying
   exclusively on scanner test IDs.
"""

import json
import logging
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.exceptions import AegisError
from app.engine.contracts import NormalizedTestResult
from app.models.framework import (
    FindingFrameworkMapping,
    FrameworkControl,
    SecurityFramework,
)

logger = logging.getLogger("aegis.engine.framework_mapper")

KNOWLEDGE_BASE_DIR = Path(__file__).resolve().parents[1] / "knowledge_base"

AUTHORITATIVE_KB_FILES: tuple[str, ...] = (
    "owasp_llm_2026.json",
    "owasp_agentic_2026.json",
    "owasp_aisvs_v1.json",
    "nist_ai_rmf_600_1.json",
    "mitre_atlas.json",
    "iso_42001_23894.json",
)


class MappingRelationshipType(StrEnum):
    """Canonical relationship types linking a Finding to an authoritative FrameworkControl."""

    DIRECT = "DIRECT"  # Primary technical vulnerability or attack technique directly proven by evidence
    RELATED = "RELATED"  # Coupled secondary technical risk or adjacent control triggered by specific evidence
    SUPPORTING = "SUPPORTING"  # Governance, lifecycle verification, risk management, or telemetry control


class ImmutableFrameworkVersionError(AegisError):
    """Raised when an operation attempts to mutate or overwrite an existing immutable framework version."""

    def __init__(self, framework_id: str, message: str) -> None:
        super().__init__(
            code="IMMUTABLE_FRAMEWORK_VERSION_VIOLATION",
            message=message,
            status_code=409,
            details={"framework_id": framework_id},
        )


class FrameworkMetadataSchema(BaseModel):
    """Validated schema for a SecurityFramework seed header."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=3, max_length=60)
    name: str = Field(min_length=3, max_length=160)
    version: str = Field(min_length=1, max_length=40)
    publisher: str = Field(min_length=2, max_length=100)
    release_date: str = Field(default="", max_length=40)
    official_url: str = Field(min_length=8, max_length=512)
    description: str = Field(default="")

    @field_validator("official_url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("official_url must begin with https:// or http://")
        return value


class FrameworkControlSeedSchema(BaseModel):
    """Validated schema for an authoritative FrameworkControl entry."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=4, max_length=80)
    control_id: str = Field(min_length=1, max_length=50)
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(min_length=10)
    category: str = Field(min_length=2, max_length=100)
    applicable_architectures: list[str] = Field(min_length=1)
    official_reference_url: str = Field(min_length=8, max_length=512)

    @field_validator("official_reference_url")
    @classmethod
    def _validate_ref_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("official_reference_url must begin with https:// or http://")
        return value


class FrameworkBundleSchema(BaseModel):
    """Complete validated JSON bundle for one versioned security framework."""

    model_config = ConfigDict(extra="forbid")

    framework: FrameworkMetadataSchema
    controls: list[FrameworkControlSeedSchema] = Field(default_factory=list)

    @field_validator("controls")
    @classmethod
    def _validate_unique_control_ids(
        cls, controls: list[FrameworkControlSeedSchema], info: Any
    ) -> list[FrameworkControlSeedSchema]:
        fw = info.data.get("framework")
        fw_id = fw.id if fw else ""
        seen_ids: set[str] = set()
        for ctrl in controls:
            if fw_id and not ctrl.id.startswith(f"{fw_id}:"):
                raise ValueError(
                    f"Control composite id '{ctrl.id}' must start with framework id prefix '{fw_id}:'."
                )
            if ctrl.id in seen_ids:
                raise ValueError(f"Duplicate control id '{ctrl.id}' in framework '{fw_id}'.")
            seen_ids.add(ctrl.id)
        return controls


class ResolvedFrameworkMapping(BaseModel):
    """Fully resolved, evidence-driven framework control mapping with immutable version snapshot fields."""

    model_config = ConfigDict(extra="ignore")

    framework_control_id: str
    framework_id: str
    framework_name: str
    framework_version: str
    publisher: str
    control_id: str
    title: str
    category: str
    official_reference_url: str
    mapping_type: MappingRelationshipType
    mapping_rationale: str


@lru_cache(maxsize=1)
def load_authoritative_framework_bundles() -> tuple[FrameworkBundleSchema, ...]:
    """Load and schema-validate all 6 authoritative framework JSON files from disk."""
    bundles: list[FrameworkBundleSchema] = []
    for filename in AUTHORITATIVE_KB_FILES:
        file_path = KNOWLEDGE_BASE_DIR / filename
        raw_data = json.loads(file_path.read_text(encoding="utf-8"))
        bundle = FrameworkBundleSchema.model_validate(raw_data)
        bundles.append(bundle)
    return tuple(bundles)


def seed_framework_bundle(
    db: Session,
    bundle: FrameworkBundleSchema | dict[str, Any],
    *,
    enforce_immutability: bool = True,
) -> SecurityFramework:
    """Seed a single versioned framework bundle into the database while enforcing version immutability.

    Once a `SecurityFramework` with `id` is persisted, its `version`, metadata, and existing
    `FrameworkControl` definitions are immutable. Any update to a standard must be registered under
    a new versioned `framework.id` (e.g., `OWASP_LLM_2027`) so historical assessments retain their
    original framework references.
    """
    validated = (
        bundle
        if isinstance(bundle, FrameworkBundleSchema)
        else FrameworkBundleSchema.model_validate(bundle)
    )
    fw_meta = validated.framework
    existing_fw = (
        db.query(SecurityFramework)
        .filter(SecurityFramework.id == fw_meta.id)
        .first()
    )

    if existing_fw is not None:
        if enforce_immutability and (
            existing_fw.version != fw_meta.version
            or existing_fw.name != fw_meta.name
            or existing_fw.publisher != fw_meta.publisher
            or (
                fw_meta.release_date
                and existing_fw.release_date
                and existing_fw.release_date != fw_meta.release_date
            )
            or (
                fw_meta.description
                and existing_fw.description
                and existing_fw.description != fw_meta.description
            )
        ):
            raise ImmutableFrameworkVersionError(
                fw_meta.id,
                f"Framework '{fw_meta.id}' (version '{existing_fw.version}') is immutable and cannot be "
                f"overwritten with version '{fw_meta.version}' or modified metadata. "
                "Register a new versioned framework ID instead.",
            )
    else:
        existing_fw = SecurityFramework(
            id=fw_meta.id,
            name=fw_meta.name,
            version=fw_meta.version,
            publisher=fw_meta.publisher,
            release_date=fw_meta.release_date,
            official_url=fw_meta.official_url,
            description=fw_meta.description,
        )
        db.add(existing_fw)
        db.flush()

    existing_controls = {
        c.id: c
        for c in db.query(FrameworkControl)
        .filter(FrameworkControl.framework_id == fw_meta.id)
        .all()
    }

    for ctrl in validated.controls:
        existing_ctrl = existing_controls.get(ctrl.id)
        if existing_ctrl is not None:
            if enforce_immutability and (
                existing_ctrl.control_id != ctrl.control_id
                or existing_ctrl.title != ctrl.title
                or existing_ctrl.description != ctrl.description
            ):
                raise ImmutableFrameworkVersionError(
                    fw_meta.id,
                    f"Control '{ctrl.id}' in framework '{fw_meta.id}@{existing_fw.version}' is immutable "
                    "and cannot be modified in place. Create a new framework version to publish updated controls.",
                )
        else:
            db.add(
                FrameworkControl(
                    id=ctrl.id,
                    framework_id=fw_meta.id,
                    control_id=ctrl.control_id,
                    title=ctrl.title,
                    description=ctrl.description,
                    category=ctrl.category,
                    applicable_architectures=list(ctrl.applicable_architectures),
                    official_reference_url=ctrl.official_reference_url,
                )
            )

    db.flush()
    return existing_fw


def ensure_knowledge_base_seeded(db: Session) -> dict[str, SecurityFramework]:
    """Idempotently seed all authoritative security frameworks into `db` if not already present."""
    bundles = load_authoritative_framework_bundles()
    seeded: dict[str, SecurityFramework] = {}
    for bundle in bundles:
        fw = seed_framework_bundle(db, bundle, enforce_immutability=True)
        seeded[fw.id] = fw
    db.commit()
    return seeded


class KnowledgeBaseLoader:
    """Object-oriented loader and idempotent seeder for the 6 authoritative security frameworks."""

    def __init__(self, kb_dir: Path = KNOWLEDGE_BASE_DIR) -> None:
        self.kb_dir = kb_dir

    @staticmethod
    def load_bundles() -> tuple[FrameworkBundleSchema, ...]:
        """Load and schema-validate all 6 authoritative framework JSON bundles."""
        return load_authoritative_framework_bundles()

    @staticmethod
    def seed_bundle(
        db: Session,
        bundle: FrameworkBundleSchema | dict[str, Any],
        *,
        enforce_immutability: bool = True,
    ) -> SecurityFramework:
        """Seed a single versioned framework bundle with immutability enforcement."""
        return seed_framework_bundle(
            db, bundle, enforce_immutability=enforce_immutability
        )

    @staticmethod
    def ensure_seeded(db: Session) -> dict[str, SecurityFramework]:
        """Idempotently seed all 6 authoritative security frameworks and return `{framework_id: SecurityFramework}`."""
        return ensure_knowledge_base_seeded(db)


def normalize_mapping_relationship(raw_type: str | None) -> MappingRelationshipType:
    """Normalize relationship type strings into DIRECT, RELATED, or SUPPORTING."""
    cleaned = (raw_type or "DIRECT").strip().upper()
    if cleaned == MappingRelationshipType.DIRECT.value:
        return MappingRelationshipType.DIRECT
    if cleaned == MappingRelationshipType.RELATED.value:
        return MappingRelationshipType.RELATED
    if cleaned in (MappingRelationshipType.SUPPORTING.value, "CONCEPTUAL", "GOVERNANCE"):
        return MappingRelationshipType.SUPPORTING
    return MappingRelationshipType.RELATED


class FrameworkMappingEngine:
    """Evidence-driven conditional mapping engine linking findings to versioned framework controls."""

    def __init__(self, db: Session) -> None:
        self.db = db
        ensure_knowledge_base_seeded(self.db)

    def _summarize_evidence_signals(self, norm_result: NormalizedTestResult) -> dict[str, Any]:
        """Extract detector types, matched indicators, and runtime vs static signals from evidence."""
        detector_types: list[str] = []
        indicators: list[str] = []
        probe_names: list[str] = []

        for ev in norm_result.technical_evidence:
            if ev.detector_type and ev.detector_type not in detector_types:
                detector_types.append(ev.detector_type)
            if ev.probe_name and ev.probe_name not in probe_names:
                probe_names.append(ev.probe_name)
            for ind in ev.matched_indicators:
                if ind and ind not in indicators:
                    indicators.append(ind)

        indicators_blob = " | ".join(indicators).lower()
        detectors_set = set(detector_types)

        has_runtime_det = bool(detectors_set - {"CONFIG_RULE"})
        has_config_rule = "CONFIG_RULE" in detectors_set

        return {
            "detector_types": detector_types,
            "detectors_set": detectors_set,
            "indicators": indicators,
            "indicators_blob": indicators_blob,
            "probe_names": probe_names,
            "has_runtime_det": has_runtime_det,
            "has_config_rule": has_config_rule,
        }

    def _format_evidence_citation(
        self,
        norm_result: NormalizedTestResult,
        signals: dict[str, Any],
    ) -> str:
        """Build a concise evidence citation suffix explaining what triggered the mapping."""
        detectors = signals["detector_types"] or ["DETERMINISTIC_EVALUATOR"]
        sample_indicators = signals["indicators"][:2]
        status_label = (
            "confirmed runtime/config evidence"
            if norm_result.execution_status.value == "FAIL"
            else "ambiguous behavioral indicator (NEEDS_REVIEW)"
        )
        if sample_indicators:
            ind_preview = "; ".join(str(i)[:90] for i in sample_indicators)
            return (
                f"Evidence basis ({status_label}): detector={','.join(detectors)} "
                f"on component '{norm_result.target_component}' [{ind_preview}]."
            )
        return (
            f"Evidence basis ({status_label}): detector={','.join(detectors)} "
            f"on component '{norm_result.target_component}'."
        )

    def _evaluate_conditional_rules(
        self,
        norm_result: NormalizedTestResult,
        architecture_type: str,
        signals: dict[str, Any],
    ) -> list[tuple[str, MappingRelationshipType, str]]:
        """Evaluate conditional applicability rules based on evidence detectors, indicators, component, and architecture."""
        candidates: list[tuple[str, MappingRelationshipType, str]] = []
        test_id = norm_result.test_id.upper()
        comp = (norm_result.target_component or "").upper()
        cat = (norm_result.test_category or "").upper()
        module = (norm_result.module or "").upper()
        det_set: set[str] = signals["detectors_set"]
        ind_blob: str = signals["indicators_blob"]

        # -------------------------------------------------------------------
        # A. Direct & Indirect Prompt Injection Conditional Rules
        # -------------------------------------------------------------------
        is_direct_pi = (
            test_id == "LLM-PI-001"
            or ("DIRECT" in cat and "INJECTION" in cat)
            or (
                "CANARY_TOKEN_MATCH" in det_set
                and comp == "LLM_SYSTEM_PROMPT_BOUNDARY"
                and "INDIRECT" not in cat
            )
        )
        if is_direct_pi:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM01",
                        MappingRelationshipType.DIRECT,
                        "Direct prompt injection payload subverted the system instruction hierarchy.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.000",
                        MappingRelationshipType.DIRECT,
                        "Probe demonstrated direct LLM prompt injection (AML.T0051.000) via user input.",
                    ),
                    (
                        "OWASP_AISVS_V1:C2",
                        MappingRelationshipType.DIRECT,
                        "Input boundary and prompt delimiter validation (AISVS C2) failed to isolate user input.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0054",
                        MappingRelationshipType.RELATED,
                        "Instruction override and constraint bypass probes overlap with LLM guardrail evasion (AML.T0054).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.7",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.7 adversarial prompt-injection resilience evaluation.",
                    ),
                    (
                        "ISO_42001_23894:A.6.2.4",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.6.2.4 verification and validation of prompt boundary controls.",
                    ),
                ]
            )

        is_indirect_pi = (
            test_id == "LLM-PI-002"
            or (module == "LLM" and "INDIRECT" in cat and "INJECTION" in cat)
            or comp == "LLM_CONTEXT_INGESTION_BOUNDARY"
        )
        if is_indirect_pi:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM01",
                        MappingRelationshipType.DIRECT,
                        "Untrusted external context payload hijacked model instruction execution (LLM01:2026).",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.001",
                        MappingRelationshipType.DIRECT,
                        "Demonstrated indirect prompt injection via ingested external context documents (AML.T0051.001).",
                    ),
                    (
                        "OWASP_AISVS_V1:C2",
                        MappingRelationshipType.DIRECT,
                        "External context lacked effective spotlighting or data-marking boundary controls (AISVS C2).",
                    ),
                    (
                        "OWASP_LLM_2026:LLM05",
                        MappingRelationshipType.RELATED,
                        "Poisoned external context ingestion creates a data/context poisoning vector (LLM05:2026).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MP-4.1",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MAP 4.1 risk mapping for third-party and external context data.",
                    ),
                    (
                        "ISO_42001_23894:A.7.4",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.7.4 data provenance and hygiene requirements for ingested context.",
                    ),
                ]
            )

        # -------------------------------------------------------------------
        # B. System Prompt Exposure Conditional Rules
        # -------------------------------------------------------------------
        is_spe = (
            test_id == "LLM-SPE-001"
            or "SYSTEM PROMPT" in cat
            or "SYSTEM_PROMPT_SIMILARITY" in det_set
            or "cfg-spe-001" in ind_blob
        )
        if is_spe:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM08",
                        MappingRelationshipType.DIRECT,
                        "Target disclosed confidential system prompt instructions or hidden configuration preamble (LLM08:2026).",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0056",
                        MappingRelationshipType.DIRECT,
                        "Demonstrated susceptibility to MITRE ATLAS AML.T0056 (LLM Meta Prompt Extraction).",
                    ),
                    (
                        "OWASP_AISVS_V1:C5",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C5 System Prompt Confidentiality and Secret Exclusion requirements.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.000",
                        MappingRelationshipType.RELATED,
                        "Meta-prompt extraction was elicited via direct instruction-boundary probing (AML.T0051.000).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.7",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.7 evaluation of meta-prompt extraction resistance.",
                    ),
                    (
                        "ISO_42001_23894:A.6.2.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.6.2.3 secure system design separating secrets from prompts.",
                    ),
                ]
            )
            # Conditional evidence check: did the system prompt contain a hardcoded secret (CFG-SPE-001)?
            if "cfg-spe-001" in ind_blob or "secret" in ind_blob or "api_key" in ind_blob:
                candidates.extend(
                    [
                        (
                            "OWASP_LLM_2026:LLM02",
                            MappingRelationshipType.RELATED,
                            "Hardcoded credentials/secrets detected in the system prompt escalate exposure to Sensitive Information Disclosure (LLM02:2026).",
                        ),
                        (
                            "OWASP_AISVS_V1:C4",
                            MappingRelationshipType.RELATED,
                            "Hardcoded secret in system prompt violates AISVS C4 Secret & Credential Protection.",
                        ),
                    ]
                )

        # -------------------------------------------------------------------
        # C. Sensitive Information / Secret / PII Disclosure Conditional Rules
        # -------------------------------------------------------------------
        is_sid = (
            test_id == "LLM-SID-001"
            or "SENSITIVE INFORMATION" in cat
            or "SECRET_AND_PII_DETECTOR" in det_set
            or comp == "LLM_OUTPUT_DLP_FILTER"
        )
        if is_sid:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM02",
                        MappingRelationshipType.DIRECT,
                        "Target emitted sensitive credentials or regulated PII patterns without outbound DLP redaction (LLM02:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C4",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C4 Data Privacy, PII Scrubbing, and Secret Protection controls.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0048",
                        MappingRelationshipType.RELATED,
                        "Disclosure of runtime secrets or memorized PII enables sensitive data exfiltration (AML.T0048).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.10",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.10 examination of privacy risk and sensitive data leakage.",
                    ),
                    (
                        "ISO_42001_23894:A.5.2",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.5.2 assessment of privacy and credential exposure impacts.",
                    ),
                ]
            )
            if "aws access key" in ind_blob or "api secret key" in ind_blob or "jwt" in ind_blob:
                candidates.append(
                    (
                        "OWASP_AISVS_V1:C11",
                        MappingRelationshipType.RELATED,
                        "Evidence of leaked runtime API/cloud credentials indicates missing runtime secret isolation (AISVS C11).",
                    )
                )

        # -------------------------------------------------------------------
        # D. Improper Output Handling Conditional Rules (XSS vs Markdown Beacon vs SQL)
        # -------------------------------------------------------------------
        is_ioh = (
            test_id == "LLM-IOH-001"
            or "OUTPUT HANDLING" in cat
            or "SINK_AST_DETECTOR" in det_set
            or comp == "LLM_OUTPUT_SINK"
        )
        if is_ioh:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM10",
                        MappingRelationshipType.DIRECT,
                        "Target emitted unescaped executable output sink payloads (HTML/XSS, Markdown beacon, or SQL) (LLM10:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C3",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C3 Output Encoding, Sanitization, and Sink Protection requirements.",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.5",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.5 output safety validation and downstream sink reliability.",
                    ),
                    (
                        "ISO_42001_23894:A.8.2",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.8.2 safe downstream consumption of AI outputs.",
                    ),
                ]
            )
            if "markdown image beacon" in ind_blob or "canary.aegis.invalid" in ind_blob:
                candidates.extend(
                    [
                        (
                            "MITRE_ATLAS:AML.T0048",
                            MappingRelationshipType.RELATED,
                            "Evidence includes rendered external Markdown image beacons enabling zero-click data exfiltration (AML.T0048).",
                        ),
                        (
                            "OWASP_LLM_2026:LLM02",
                            MappingRelationshipType.RELATED,
                            "External Markdown image beacon rendering provides an exfiltration channel for sensitive context (LLM02:2026).",
                        ),
                    ]
                )
            if "sql sink payload" in ind_blob or "select * from" in ind_blob:
                candidates.append(
                    (
                        "OWASP_AGENTIC_2026:ASI06",
                        MappingRelationshipType.RELATED,
                        "Emission of raw unparameterized SQL clauses exposes downstream database execution sinks (ASI06).",
                    )
                )

        # -------------------------------------------------------------------
        # E. Unbounded Consumption & Model Configuration Conditional Rules
        # -------------------------------------------------------------------
        is_cfg = (
            test_id == "LLM-CFG-001"
            or "UNBOUNDED CONSUMPTION" in cat
            or "UNBOUNDED_CONSUMPTION_DETECTOR" in det_set
            or comp == "LLM_MODEL_CONFIG"
        )
        if is_cfg:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM06",
                        MappingRelationshipType.DIRECT,
                        "Target lacks generation ceilings or accepted unbounded token consumption probes (LLM06:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C9",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C9 Execution Budgets, Token Ceilings, and Generation Parameter Bounds.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0040",
                        MappingRelationshipType.RELATED,
                        "Unbounded inference token generation enables ML Model Inference API resource exhaustion (AML.T0040).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.6",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.6 computational resource consumption and safety limit evaluation.",
                    ),
                    (
                        "ISO_42001_23894:A.6.2.5",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.6.2.5 operational resource and deployment parameter limits.",
                    ),
                ]
            )

        # -------------------------------------------------------------------
        # F. RAG Security Conditional Rules (RAG-AUTH-001, RAG-IPI-001, RAG-META-001, RAG-ARCH-001)
        # -------------------------------------------------------------------
        is_rag_auth = (
            test_id == "RAG-AUTH-001"
            or "CROSS-TENANT" in cat
            or "RAG_CROSS_TENANT_DETECTOR" in det_set
            or comp == "RAG_TENANT_ACL_FILTER"
        )
        if is_rag_auth:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM09",
                        MappingRelationshipType.DIRECT,
                        "Vector similarity retrieval failed to isolate tenant namespaces, leaking foreign tenant chunks (LLM09:2026).",
                    ),
                    (
                        "OWASP_LLM_2026:LLM02",
                        MappingRelationshipType.DIRECT,
                        "Cross-tenant RAG retrieval directly disclosed confidential documents owned by another tenant (LLM02:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C8",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C8 Vector Database Tenant ACL Pre-Filtering requirements.",
                    ),
                    (
                        "OWASP_AISVS_V1:C7",
                        MappingRelationshipType.RELATED,
                        "Retrieval query execution was not cryptographically bound to the authenticated caller's tenant identity (AISVS C7).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.10",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.10 cross-tenant privacy and data isolation verification.",
                    ),
                    (
                        "ISO_42001_23894:A.10.2",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.10.2 tenant isolation and responsibility boundaries.",
                    ),
                ]
            )

        is_rag_ipi = (
            test_id == "RAG-IPI-001"
            or "RAG INDIRECT" in cat
            or comp == "RAG_CONTEXT_ASSEMBLY_BOUNDARY"
        )
        if is_rag_ipi:
            candidates.extend(
                [
                    (
                        "MITRE_ATLAS:AML.T0071",
                        MappingRelationshipType.DIRECT,
                        "Poisoned RAG knowledge base chunks hijacked the retrieval-to-synthesis boundary (AML.T0071).",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.001",
                        MappingRelationshipType.DIRECT,
                        "Indirect prompt injection executed via retrieved RAG context passages (AML.T0051.001).",
                    ),
                    (
                        "OWASP_LLM_2026:LLM01",
                        MappingRelationshipType.DIRECT,
                        "RAG synthesis prompt succumbed to indirect prompt injection embedded in retrieved chunks (LLM01:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C8",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C8 Retrieved Context Spotlighting and Delimiter Isolation.",
                    ),
                    (
                        "OWASP_LLM_2026:LLM09",
                        MappingRelationshipType.RELATED,
                        "Unsanitized vector store chunk retrieval enabled downstream generation manipulation (LLM09:2026).",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI04",
                        MappingRelationshipType.RELATED,
                        "Poisoned retrieval context corrupts shared RAG memory state (ASI04).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.7",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.7 RAG indirect injection resilience testing.",
                    ),
                    (
                        "ISO_42001_23894:A.7.4",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.7.4 data quality and sanitization controls for RAG corpora.",
                    ),
                ]
            )

        is_rag_meta = (
            test_id == "RAG-META-001"
            or "METADATA FILTER" in cat
            or "RAG_METADATA_BYPASS_DETECTOR" in det_set
            or comp == "RAG_METADATA_FILTER"
        )
        if is_rag_meta:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM09",
                        MappingRelationshipType.DIRECT,
                        "Vector metadata filter was bypassed via operator injection or filter override (LLM09:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C8",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C8 Metadata Filter Immutability and Least-Privilege Retrieval.",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0043",
                        MappingRelationshipType.RELATED,
                        "Caller-injected NoSQL/vector filter operators ($ne, $in) represent crafted adversarial query data (AML.T0043).",
                    ),
                    (
                        "OWASP_LLM_2026:LLM02",
                        MappingRelationshipType.RELATED,
                        "Metadata filter bypass exposed RESTRICTED_EXECUTIVE chunks to unauthorized callers (LLM02:2026).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MP-2.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MAP 2.3 retrieval access boundary validation.",
                    ),
                    (
                        "ISO_42001_23894:A.6.2.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.6.2.3 architectural specification of immutable retrieval filters.",
                    ),
                ]
            )

        is_rag_arch = (
            test_id == "RAG-ARCH-001"
            or comp == "RAG_PIPELINE_CONFIG"
            or any(r in ind_blob for r in ("cfg-rag-001", "cfg-rag-002", "cfg-rag-003"))
        )
        if is_rag_arch:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM09",
                        MappingRelationshipType.DIRECT,
                        "RAG pipeline audit identified vector store ACL, chunking, or ingestion weaknesses (LLM09:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C8",
                        MappingRelationshipType.DIRECT,
                        "Directly audits AISVS C8 RAG Vector Store ACLs, Chunking Bounds, and Ingestion Hygiene.",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MP-4.1",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MAP 4.1 RAG corpus and vector pipeline risk governance.",
                    ),
                    (
                        "ISO_42001_23894:A.7.4",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.7.4 RAG data preparation and chunking governance.",
                    ),
                ]
            )
            if "cfg-rag-001" in ind_blob or "confirmed_runtime_exploitation" in ind_blob:
                candidates.append(
                    (
                        "OWASP_AISVS_V1:C7",
                        MappingRelationshipType.RELATED,
                        "Missing mandatory tenant pre-filter (CFG-RAG-001) or runtime leak compromises multi-tenant access control (AISVS C7).",
                    )
                )
            if "cfg-rag-002" in ind_blob or "cfg-rag-003" in ind_blob:
                candidates.append(
                    (
                        "OWASP_LLM_2026:LLM05",
                        MappingRelationshipType.RELATED,
                        "Oversized chunking (CFG-RAG-002) or unsanitized document ingestion (CFG-RAG-003) increases corpus poisoning risk (LLM05:2026).",
                    )
                )

        # -------------------------------------------------------------------
        # G. AI Agent Security Conditional Rules (AGT-TOOL-001, AGT-GH-001, AGT-PERM-001)
        # -------------------------------------------------------------------
        is_agt_tool = (
            test_id == "AGT-TOOL-001"
            or "TOOL MISUSE" in cat
            or comp == "AGENT_TOOL_ROUTER"
        )
        if is_agt_tool:
            candidates.extend(
                [
                    (
                        "OWASP_AGENTIC_2026:ASI02",
                        MappingRelationshipType.DIRECT,
                        "Agent tool router accepted unauthorized tool invocation or escalated JSON arguments (ASI02).",
                    ),
                    (
                        "OWASP_LLM_2026:LLM03",
                        MappingRelationshipType.DIRECT,
                        "Demonstrated excessive agency via unconstrained tool parameter manipulation (LLM03:2026).",
                    ),
                    (
                        "OWASP_AISVS_V1:C10",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C10 Agent Tool Invocation Validation and Strict Parameter Enforcement.",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI03",
                        MappingRelationshipType.RELATED,
                        "Escalation of tool parameters (e.g., scope='ALL_TENANTS') triggers confused-deputy privilege compromise (ASI03).",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.000",
                        MappingRelationshipType.RELATED,
                        "Adversarial prompt payload subverted the agent's function-calling router (AML.T0051.000).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MG-2.2",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MANAGE 2.2 controls sustaining safe agent tool execution.",
                    ),
                    (
                        "ISO_42001_23894:A.6.2.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.6.2.3 strict schema specification for agent tools.",
                    ),
                ]
            )

        is_agt_gh = (
            test_id == "AGT-GH-001"
            or "GOAL HIJACKING" in cat
            or comp == "AGENT_PLANNER_GOAL_STATE"
        )
        if is_agt_gh:
            candidates.extend(
                [
                    (
                        "OWASP_AGENTIC_2026:ASI01",
                        MappingRelationshipType.DIRECT,
                        "Untrusted external context hijacked the autonomous agent's planner goal state (ASI01).",
                    ),
                    (
                        "MITRE_ATLAS:AML.T0051.001",
                        MappingRelationshipType.DIRECT,
                        "Indirect prompt injection inside ingested context diverted agent execution (AML.T0051.001).",
                    ),
                    (
                        "OWASP_AISVS_V1:C9",
                        MappingRelationshipType.DIRECT,
                        "Violates AISVS C9 Agent Goal Integrity and Planner Boundary Isolation.",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI02",
                        MappingRelationshipType.RELATED,
                        "Hijacked planner goal state induced unauthorized downstream tool invocation (ASI02).",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI04",
                        MappingRelationshipType.RELATED,
                        "Adversarial context directives polluted the agent's working memory state (ASI04).",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MS-2.7",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.7 evaluation of autonomous agent goal-hijacking resilience.",
                    ),
                    (
                        "ISO_42001_23894:A.9.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.9.3 human oversight over goal changes in autonomous systems.",
                    ),
                ]
            )

        is_agt_perm = (
            test_id == "AGT-PERM-001"
            or "HUMAN-IN-THE-LOOP" in cat
            or comp == "AGENT_HITL_APPROVAL_GATE"
            or any(r in ind_blob for r in ("cfg-agt-001", "cfg-agt-002", "cfg-agt-003"))
        )
        if is_agt_perm:
            candidates.extend(
                [
                    (
                        "OWASP_LLM_2026:LLM03",
                        MappingRelationshipType.DIRECT,
                        "Agent exhibited excessive agency or lacked mandatory approval and schema constraints (LLM03:2026).",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI03",
                        MappingRelationshipType.DIRECT,
                        "Over-privileged autonomous tool execution without scoped delegation guardrails (ASI03).",
                    ),
                    (
                        "OWASP_AGENTIC_2026:ASI09",
                        MappingRelationshipType.DIRECT,
                        "Missing or bypassable Human-in-the-Loop approval gate for privileged tool execution (ASI09).",
                    ),
                    (
                        "OWASP_AISVS_V1:C9",
                        MappingRelationshipType.DIRECT,
                        "Audits AISVS C9 Agent Execution Budgets and Iteration Ceilings.",
                    ),
                    (
                        "OWASP_AISVS_V1:C10",
                        MappingRelationshipType.DIRECT,
                        "Audits AISVS C10 Tool JSON Schema Constraints and HITL Enforcement.",
                    ),
                    (
                        "NIST_AI_RMF_600_1:MG-2.2",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MANAGE 2.2 human oversight and operational safety controls.",
                    ),
                    (
                        "ISO_42001_23894:A.9.3",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 42001 Annex A.9.3 Human Oversight of AI Systems.",
                    ),
                ]
            )
            if "cfg-agt-002" in ind_blob:
                candidates.extend(
                    [
                        (
                            "OWASP_AGENTIC_2026:ASI05",
                            MappingRelationshipType.RELATED,
                            "Unbounded or excessive max_iterations budget (CFG-AGT-002) enables cascading reasoning loops (ASI05).",
                        ),
                        (
                            "OWASP_LLM_2026:LLM06",
                            MappingRelationshipType.RELATED,
                            "Excessive agent loop iteration ceiling (CFG-AGT-002) exposes the system to unbounded resource consumption (LLM06:2026).",
                        ),
                    ]
                )
            if "cfg-agt-003" in ind_blob:
                candidates.append(
                    (
                        "OWASP_AGENTIC_2026:ASI08",
                        MappingRelationshipType.RELATED,
                        "Permissive tool schema ('additionalProperties: true' in CFG-AGT-003) weakens agent tool schema integrity (ASI08).",
                    )
                )

        # -------------------------------------------------------------------
        # H. Generic Fallback for Custom Plugins (when no specific branch matched)
        # -------------------------------------------------------------------
        if not candidates and not norm_result.framework_references:
            if "CANARY_TOKEN_MATCH" in det_set:
                candidates.extend(
                    [
                        (
                            "OWASP_LLM_2026:LLM01",
                            MappingRelationshipType.DIRECT,
                            "Deterministic canary token reflection indicates prompt or instruction boundary override (LLM01:2026).",
                        ),
                        (
                            "OWASP_AISVS_V1:C2",
                            MappingRelationshipType.RELATED,
                            "Input boundary control failed to prevent canary directive execution (AISVS C2).",
                        ),
                    ]
                )
            candidates.extend(
                [
                    (
                        "NIST_AI_RMF_600_1:MS-2.7",
                        MappingRelationshipType.SUPPORTING,
                        "Supports NIST AI RMF MEASURE 2.7 security testing and evaluation.",
                    ),
                    (
                        "ISO_42001_23894:ISO23894-6.4",
                        MappingRelationshipType.SUPPORTING,
                        "Supports ISO/IEC 23894 Clause 6.4 AI risk analysis and evaluation.",
                    ),
                ]
            )

        # Always attach ISO/IEC 23894 Clause 6.5 (Risk Treatment & Verification) as SUPPORTING governance
        candidates.append(
            (
                "ISO_42001_23894:ISO23894-6.5",
                MappingRelationshipType.SUPPORTING,
                "Supports ISO/IEC 23894 Clause 6.5 AI risk treatment and post-remediation control verification.",
            )
        )
        return candidates

    def resolve_mappings_for_result(
        self,
        norm_result: NormalizedTestResult,
        *,
        architecture_type: str = "LLM_APP",
    ) -> list[ResolvedFrameworkMapping]:
        """Resolve and deduplicate DIRECT, RELATED, and SUPPORTING framework mappings for `norm_result`."""
        signals = self._summarize_evidence_signals(norm_result)
        evidence_citation = self._format_evidence_citation(norm_result, signals)
        arch = (architecture_type or "LLM_APP").upper()

        # Ordered dictionary keyed by framework_control_id -> (MappingRelationshipType, base_rationale)
        ordered_candidates: dict[str, tuple[MappingRelationshipType, str]] = {}

        # 1. Start with explicit references provided by the plugin
        for ref in norm_result.framework_references:
            if not isinstance(ref, dict):
                continue
            ctrl_id = str(ref.get("framework_control_id") or ref.get("id") or "").strip()
            if not ctrl_id:
                continue
            rel_type = normalize_mapping_relationship(str(ref.get("mapping_type") or "DIRECT"))
            base_rat = str(
                ref.get("mapping_rationale")
                or f"Mapped from security test {norm_result.test_id}."
            ).strip()
            ordered_candidates[ctrl_id] = (rel_type, base_rat)

        # 2. Merge evidence-driven conditional rules
        for ctrl_id, rel_type, cond_rationale in self._evaluate_conditional_rules(
            norm_result, arch, signals
        ):
            if ctrl_id not in ordered_candidates:
                ordered_candidates[ctrl_id] = (rel_type, cond_rationale)

        # 3. Query authoritative controls and parent frameworks in batch
        if not ordered_candidates:
            return []

        ctrl_rows = (
            self.db.query(FrameworkControl)
            .filter(FrameworkControl.id.in_(list(ordered_candidates.keys())))
            .all()
        )
        ctrl_by_id = {c.id: c for c in ctrl_rows}

        fw_ids = {c.framework_id for c in ctrl_rows}
        fw_rows = (
            self.db.query(SecurityFramework)
            .filter(SecurityFramework.id.in_(list(fw_ids)))
            .all()
            if fw_ids
            else []
        )
        fw_by_id = {f.id: f for f in fw_rows}

        resolved: list[ResolvedFrameworkMapping] = []
        for ctrl_id, (rel_type, base_rat) in ordered_candidates.items():
            ctrl = ctrl_by_id.get(ctrl_id)
            if ctrl is None:
                continue
            fw = fw_by_id.get(ctrl.framework_id)
            if fw is None:
                continue

            # Check conditional architecture applicability for non-DIRECT conditional mappings
            app_archs = [a.upper() for a in (ctrl.applicable_architectures or [])]
            if (
                rel_type != MappingRelationshipType.DIRECT
                and app_archs
                and arch != "HYBRID"
                and arch not in app_archs
            ):
                # Allow if the test module explicitly targeted that domain (e.g., RAG module test)
                mod = (norm_result.module or "").upper()
                if not (
                    (mod == "RAG" and "RAG_PIPELINE" in app_archs)
                    or (mod == "AGENT" and "AI_AGENT" in app_archs)
                    or (mod == "LLM" and "LLM_APP" in app_archs)
                ):
                    continue

            full_rationale = f"{base_rat} {evidence_citation}".strip()
            resolved.append(
                ResolvedFrameworkMapping(
                    framework_control_id=ctrl.id,
                    framework_id=fw.id,
                    framework_name=fw.name,
                    framework_version=fw.version,
                    publisher=fw.publisher,
                    control_id=ctrl.control_id,
                    title=ctrl.title,
                    category=ctrl.category,
                    official_reference_url=ctrl.official_reference_url,
                    mapping_type=rel_type,
                    mapping_rationale=full_rationale,
                )
            )

        return resolved

    def persist_finding_mappings(
        self,
        *,
        finding_id: str,
        resolved_mappings: list[ResolvedFrameworkMapping],
    ) -> list[FindingFrameworkMapping]:
        """Persist `FindingFrameworkMapping` rows for a Finding."""
        persisted: list[FindingFrameworkMapping] = []
        for item in resolved_mappings:
            mapping = FindingFrameworkMapping(
                finding_id=finding_id,
                framework_control_id=item.framework_control_id,
                mapping_type=item.mapping_type.value,
                mapping_rationale=item.mapping_rationale,
            )
            self.db.add(mapping)
            persisted.append(mapping)
        self.db.flush()
        return persisted
