# AegisAI — Engineering Improvement Backlog & Technical Debt Register

**Document Status:** Active Engineering Backlog (Synchronized through Phase 6 + Stage 1 Hardening)  
**Purpose:** Track completed hardening items, remaining Stage 2 scanner/knowledge-base refinements, dependency deprecation warnings, and post-MVP capability enhancements.

---

## 1. Completed Stage 1 Security & Contract Hardening Items

| ID | Component | Hardening Summary | Status |
| :--- | :--- | :--- | :--- |
| **SH-001** | `scanners/llm/plugins.py`, `adapters/simulator.py`, `api/v1/targets.py` | Enforced strict `CONFIG_ONLY` isolation across all 6 LLM scanners (`LLM-PI-001`, `LLM-PI-002`, `LLM-SID-001`, `LLM-IOH-001` marked `NOT_APPLICABLE`; `LLM-SPE-001` & `LLM-CFG-001` skip active probes), preserved static `CONFIG_RULE` findings on active transport failures, and skipped DNS resolution for `CONFIG_ONLY` target creation. | **COMPLETED (Stage 1)** |
| **SH-002** | `core/config.py` | Added `@model_validator` rejecting empty, short (`< 32` chars), or default `AEGIS_JWT_SECRET_KEY` and `AEGIS_MASTER_ENCRYPTION_KEY` in production/staging environments without echoing secret values. | **COMPLETED (Stage 1)** |
| **SH-003** | `core/logging.py`, `core/audit.py`, `engine/evidence.py` | Unified recursive secret/PII redaction across logging, audit logs, and technical evidence (`sanitize_structured_payload`, `redact_sensitive_text`), covering `token`-related dictionary keys and nested dicts, lists, and tuples without circular imports. | **COMPLETED (Stage 1)** |
| **SH-004** | `schemas/assessment.py`, `engine/registry.py`, `main.py` | Validated `selected_modules` against `ScannerModule` (`LLM`, `RAG`, `AGENT`, `CONFIG`), mapped `CONFIG` to static-config audit plugins, and guarded `validation_error_handler` with `jsonable_encoder`. | **COMPLETED (Stage 1)** |
| **SH-005** | `engine/orchestrator.py` | Added atomic `QUEUED -> PROFILING` SQL claim update + in-process concurrency guard (`_ACTIVE_ASSESSMENT_RUNS`) and `BaseException` / `CancelledError` failure recovery so interrupted assessments never remain stuck in `EXECUTING_TESTS`. | **COMPLETED (Stage 1)** |
| **SH-006** | `engine/adapters/base.py` | Mitigated TOCTOU DNS rebinding by pinning outbound `SafeTargetClient` connection URLs to the validated IPv4/IPv6 address while preserving the `Host` header and TLS `sni_hostname` extension. | **COMPLETED (Stage 1)** |

---

## 2. Stage 2 Scanner Detection & Knowledge Base Refinements (Pre-Phase 8)

| ID | Component | Observation / Planned Refinement | Target Resolution Phase |
| :--- | :--- | :--- | :--- |
| **STG2-001** | `adapters/openai_compat.py` (`ENH-005`) | Frame `context_documents` inside a delimited `user` message block rather than `role: "system"` to prevent client-side privilege elevation on raw `OPENAI_COMPAT` endpoints. | **Stage 2 / Phase 8** |
| **STG2-002** | `scanners/llm/plugins.py`, `evaluators/deterministic.py` | Avoid falling back to `DEFAULT_SIMULATED_SYSTEM_PROMPT` on non-simulator targets in `LLM-SPE-001`, add refusal disambiguation to `SystemPromptSimilarityEvaluator`, and make `DeterministicCanaryMatcher` case-insensitive. | **Stage 2 / Phase 8** |
| **STG2-003** | `engine/framework_mapper.py`, `api/v1/frameworks.py` | Enforce control-set count immutability in `seed_framework_bundle()`, snapshot `total_controls` in `framework_kb_snapshot`, and align `RAG_METADATA_FILTER_DETECTOR` name in `_evaluate_conditional_rules`. | **Stage 2 / Phase 8** |
| **STG2-004** | `engine/report_generator.py` | Add line wrapping and multi-page pagination to `build_pdf_bytes_from_report_payload()`. | **Stage 2 / Phase 8** |

---

## 3. Dependency & Test Harness Maintenance

| ID | Component | Observation / Warning | Impact | Target Resolution Phase |
| :--- | :--- | :--- | :--- | :--- |
| **TD-001** | `starlette.testclient` / `httpx` | `fastapi.testclient` / `starlette.testclient` emits `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.` during test runs. | Non-breaking warning during `pytest` execution; 0 test failures. | **Phase 8** (End-to-End Validation & Dependency Hardening) |

---

## 2. Assessment Engine & Scanner Enhancements (Post-MVP Evolution)

| ID | Module / Area | Enhancement Description | Rationale |
| :--- | :--- | :--- | :--- |
| **ENH-001** | **Module C (Agent Scanner)** | **Out-of-Band (OOB) Loopback Canary Receiver:** Provide an optional internal FastAPI loopback callback recorder (`/api/v1/internal/canary-sink/{nonce}`) for asynchronous agent architectures that do not return `tool_calls` synchronously in the HTTP response body. | Current MVP agent tests inspect structured dry-run `tool_calls` telemetry and response envelopes synchronously to guarantee zero external side effects. |
| **ENH-002** | **Module B (RAG Scanner)** | **Automated Ephemeral Canary Document Seeding API Hook:** Add an optional pre-scan hook in `RAGHarnessAdapter` that uploads a synthetic Tenant A canary document (`AEGIS-CANARY-...`) via a customer-configured ingestion endpoint and purges it in a `finally` block post-scan. | Current Level 2 RAG harness supports pre-seeded synthetic canary identifiers and request-time `injected_documents` context injection. |
| **ENH-003** | **Configuration & Source Analysis** | **AST Source-Code Scanner (`SourceCodeScanner`):** Static Python/TypeScript AST analyzer to inspect LangChain, LlamaIndex, and MCP server codebases for missing tenant filter clauses and unconstrained tool decorators (`PROJECT_PLAN.md` Section 3.2). | Deferred from initial MVP per `PROJECT_PLAN.md` Section 3.2 to prioritize deterministic runtime and manifest verification. |
| **ENH-004** | **Multi-Modal LLM Security** | **Multi-Modal Indirect Injection Probes:** Image and PDF metadata/OCR steganographic prompt injection probes (`PROJECT_PLAN.md` Section 3.2). | Out-of-scope for initial text/JSON MVP scanner suites. |
| **ENH-005** | **Target Adapters (`OpenAICompatibleAdapter`)** | **Configurable Untrusted Context Role Framing:** Allow `OpenAICompatibleAdapter` to inject `context_documents` inside a delimited `user` or `tool` message block rather than a `system` message when testing `OPENAI_COMPAT` targets without a dedicated RAG harness endpoint. | Prevents client-side privilege elevation of synthetic `context_documents` on raw `OPENAI_COMPAT` endpoints while preserving backward compatibility with Phase 3 adapter contracts. |
