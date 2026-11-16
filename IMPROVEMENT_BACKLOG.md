# AegisAI — Engineering Improvement Backlog & Technical Debt Register

**Document Status:** Active Engineering Backlog (Synchronized through Phase 6)  
**Purpose:** Track non-blocking technical debt, dependency deprecation warnings, and post-MVP capability enhancements without introducing scope creep into active phases.

---

## 1. Dependency & Test Harness Maintenance

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
