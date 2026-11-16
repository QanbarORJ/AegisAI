"""Architecture & Configuration Manifest Static Analyzer (`ConfigurationAnalyzer`).

Implements ARCHITECTURE.md Section 4.1 (State 4: ANALYZING_ARCHITECTURE) and ROADMAP.md Phase 3:
- Inspects declared system prompt templates, model generation parameters, RAG vector store configs,
  and Agent/MCP tool schemas.
- Pinpoints architectural components, records static configuration weaknesses, and computes
  compensating control multipliers for AVSS v1.0 risk scoring.
"""

from typing import Any

from app.engine.contracts import ArchitectureAnalysisResult
from app.engine.evidence import detect_and_mask_sensitive_artifacts


class ConfigurationAnalyzer:
    """Static analyzer for target architecture manifests and harness configurations."""

    def analyze(
        self,
        *,
        architecture_type: str,
        architecture_manifest: dict[str, Any] | None = None,
        rag_harness_config: dict[str, Any] | None = None,
        agent_harness_config: dict[str, Any] | None = None,
    ) -> ArchitectureAnalysisResult:
        arch = (architecture_type or "LLM_APP").upper()
        manifest = architecture_manifest or {}
        rag_cfg = rag_harness_config or manifest.get("rag_config") or {}
        if not isinstance(rag_cfg, dict):
            rag_cfg = {}
        agent_cfg = agent_harness_config or manifest.get("agent_config") or {}
        if not isinstance(agent_cfg, dict):
            agent_cfg = {}

        components: list[str] = [
            "LLM_CORE",
            "LLM_SYSTEM_PROMPT_BOUNDARY",
            "LLM_OUTPUT_SINK",
        ]
        if arch in ("RAG_PIPELINE", "HYBRID") or rag_cfg:
            components.extend(
                [
                    "RAG_INGESTION_CHUNKER",
                    "RAG_EMBEDDING_PIPELINE",
                    "RAG_VECTOR_SIMILARITY_SEARCH",
                    "RAG_METADATA_FILTER",
                ]
            )
        if arch in ("AI_AGENT", "HYBRID") or agent_cfg:
            components.extend(
                [
                    "AGENT_PLANNER_GOAL_STATE",
                    "AGENT_TOOL_ROUTER",
                    "AGENT_HITL_APPROVAL_GATE",
                ]
            )

        weaknesses: list[dict[str, Any]] = []
        compensating_controls: list[str] = []

        # 1. Analyze LLM Model & Generation Parameters
        model_cfg = manifest.get("model_config")
        if not isinstance(model_cfg, dict):
            model_cfg = manifest

        max_tokens = model_cfg.get("max_tokens")
        if max_tokens is None:
            weaknesses.append(
                {
                    "rule_id": "CFG-LLM-001",
                    "component": "LLM_MODEL_CONFIG",
                    "severity": "MEDIUM",
                    "title": "Missing max_tokens Generation Ceiling",
                    "description": "No 'max_tokens' limit is declared in the model configuration, exposing the endpoint to unbounded token consumption (LLM06:2026).",
                }
            )
        elif isinstance(max_tokens, (int, float)) and max_tokens > 4096:
            weaknesses.append(
                {
                    "rule_id": "CFG-LLM-002",
                    "component": "LLM_MODEL_CONFIG",
                    "severity": "LOW",
                    "title": "Excessive max_tokens Ceiling",
                    "description": f"Configured max_tokens ({max_tokens}) exceeds recommended interactive threshold (4096).",
                }
            )

        temperature = model_cfg.get("temperature")
        if isinstance(temperature, (int, float)) and temperature > 1.0:
            weaknesses.append(
                {
                    "rule_id": "CFG-LLM-003",
                    "component": "LLM_MODEL_CONFIG",
                    "severity": "LOW",
                    "title": "High Sampling Temperature Increases Guardrail Variance",
                    "description": f"Configured temperature ({temperature}) > 1.0 increases non-deterministic policy bypass risk.",
                }
            )

        # 2. Analyze System Prompt Hygiene
        sys_prompt = str(manifest.get("system_prompt") or "")
        if sys_prompt:
            leaked_secrets = detect_and_mask_sensitive_artifacts(sys_prompt)
            if leaked_secrets:
                weaknesses.append(
                    {
                        "rule_id": "CFG-SPE-001",
                        "component": "LLM_SYSTEM_PROMPT_BOUNDARY",
                        "severity": "CRITICAL",
                        "title": "Hardcoded Secret or PII Detected in System Prompt",
                        "description": "Sensitive credentials or PII patterns are embedded directly inside the system prompt where they are vulnerable to prompt extraction (LLM08:2026).",
                        "matched_indicators": leaked_secrets,
                    }
                )

        # 3. Check Guardrail & Output Sanitization Compensating Controls
        if manifest.get("input_guardrail_enabled") is True:
            compensating_controls.append("INPUT_GUARDRAIL_ENABLED")
        if manifest.get("output_sanitization_enabled") is True or manifest.get("csp_enforced") is True:
            compensating_controls.append("OUTPUT_SANITIZATION_AND_CSP")

        # 4. Analyze RAG Pipeline Configuration (if applicable)
        if arch in ("RAG_PIPELINE", "HYBRID") or rag_cfg:
            tenant_filter = rag_cfg.get(
                "enforce_tenant_filter",
                manifest.get("enforce_tenant_filter"),
            )
            if tenant_filter is False or (tenant_filter is None and rag_cfg.get("multi_tenant", True)):
                weaknesses.append(
                    {
                        "rule_id": "CFG-RAG-001",
                        "component": "RAG_METADATA_FILTER",
                        "severity": "HIGH",
                        "title": "Missing Mandatory Tenant ACL Filter on Vector Retrieval",
                        "description": "Vector similarity search does not declare mandatory pre-filtering by 'tenant_id' (OWASP LLM09:2026 / AISVS C8).",
                    }
                )
            elif tenant_filter is True:
                compensating_controls.append("STRICT_RAG_TENANT_METADATA_FILTER")

            chunk_size = rag_cfg.get("chunk_size")
            if isinstance(chunk_size, int) and chunk_size > 2048:
                weaknesses.append(
                    {
                        "rule_id": "CFG-RAG-002",
                        "component": "RAG_INGESTION_CHUNKER",
                        "severity": "MEDIUM",
                        "title": "Oversized Document Chunking Window",
                        "description": f"Chunk size ({chunk_size} tokens) increases risk of cross-topic context bleeding and indirect injection surface.",
                    }
                )

            if rag_cfg.get("sanitize_ingested_documents") is False:
                weaknesses.append(
                    {
                        "rule_id": "CFG-RAG-003",
                        "component": "RAG_INGESTION_CHUNKER",
                        "severity": "MEDIUM",
                        "title": "Unfiltered Document Ingestion Pipeline",
                        "description": "Ingested RAG documents are not scanned or stripped of instruction-override directives prior to embedding.",
                    }
                )

        # 5. Analyze Agent & Tool Schema Configuration (if applicable)
        if arch in ("AI_AGENT", "HYBRID") or agent_cfg:
            hitl_enabled = agent_cfg.get(
                "human_in_the_loop",
                manifest.get("human_in_the_loop"),
            )
            if hitl_enabled is True:
                compensating_controls.append("AGENT_HITL_APPROVAL_GATE")
            else:
                weaknesses.append(
                    {
                        "rule_id": "CFG-AGT-001",
                        "component": "AGENT_HITL_APPROVAL_GATE",
                        "severity": "HIGH",
                        "title": "Missing Human-in-the-Loop (HITL) Approval Gate for Agent Actions",
                        "description": "Agent configuration does not enforce human approval for state-mutating or privileged tool invocations (OWASP ASI09 / LLM03:2026).",
                    }
                )

            max_steps = agent_cfg.get("max_iterations") or manifest.get("max_iterations")
            if max_steps is None or (isinstance(max_steps, int) and max_steps > 25):
                weaknesses.append(
                    {
                        "rule_id": "CFG-AGT-002",
                        "component": "AGENT_PLANNER_GOAL_STATE",
                        "severity": "MEDIUM",
                        "title": "Unbounded or Excessive Agent Execution Loop Budget",
                        "description": "Agent lacks a tight 'max_iterations' step budget (<= 25), enabling runaway recursive tool loops (AISVS C9).",
                    }
                )

            tools_list = agent_cfg.get("tools") or manifest.get("tools") or []
            if isinstance(tools_list, list):
                for tool in tools_list:
                    if not isinstance(tool, dict):
                        continue
                    t_name = str(tool.get("name") or "unnamed_tool")
                    params = tool.get("parameters")
                    if isinstance(params, dict) and params.get("additionalProperties") is True:
                        weaknesses.append(
                            {
                                "rule_id": "CFG-AGT-003",
                                "component": "AGENT_TOOL_ROUTER",
                                "severity": "MEDIUM",
                                "title": f"Unconstrained Tool Parameter Schema on '{t_name}'",
                                "description": f"Tool '{t_name}' allows arbitrary undeclared parameters ('additionalProperties: true'), facilitating parameter injection (ASI02 / AISVS C10).",
                            }
                        )

        # 6. Compute AVSS v1.0 compensating control multiplier (0.5 - 1.0)
        multiplier = 1.0
        if "AGENT_HITL_APPROVAL_GATE" in compensating_controls:
            multiplier -= 0.15
        if "STRICT_RAG_TENANT_METADATA_FILTER" in compensating_controls:
            multiplier -= 0.10
        if "INPUT_GUARDRAIL_ENABLED" in compensating_controls:
            multiplier -= 0.10
        if "OUTPUT_SANITIZATION_AND_CSP" in compensating_controls:
            multiplier -= 0.10
        multiplier = max(0.5, round(multiplier, 2))

        return ArchitectureAnalysisResult(
            architecture_type=arch,
            identified_components=components,
            config_weaknesses=weaknesses,
            compensating_controls=compensating_controls,
            compensating_multiplier=multiplier,
            summary={
                "total_components": len(components),
                "total_weaknesses": len(weaknesses),
                "compensating_controls_count": len(compensating_controls),
            },
        )
