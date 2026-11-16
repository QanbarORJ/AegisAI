"""RAG Telemetry & Dual-Tenant Harness Adapter.

Supports Level 2 Assisted / Telemetry-Enabled RAG pipelines (PROJECT_PLAN.md Section 2.2)
with dual-tenant context switching, metadata filter injection, and chunk/citation telemetry extraction.
"""

from typing import Any

from app.engine.adapters.base import SafeTargetClient, TargetAdapter
from app.engine.contracts import StandardizedTargetResponse


class RAGHarnessAdapter(TargetAdapter):
    """Adapter for RAG endpoints exposing retrieval telemetry and dual-tenant authentication."""

    def __init__(
        self,
        client: SafeTargetClient,
        *,
        request_template: dict[str, Any] | None = None,
        rag_harness_config: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(client=client)
        self.request_template = request_template or {}
        self.rag_harness_config = rag_harness_config or {}
        self.query_field = str(self.request_template.get("query_field") or "query")
        self.custom_headers = (
            self.request_template.get("headers")
            if isinstance(self.request_template.get("headers"), dict)
            else None
        )

    async def send_prompt(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        context_documents: list[str] | None = None,
        tenant_role: str = "primary",
        tools: list[dict[str, Any]] | None = None,
        extra_payload: dict[str, Any] | None = None,
    ) -> StandardizedTargetResponse:
        if self.client is None:
            raise RuntimeError("RAGHarnessAdapter requires a configured SafeTargetClient.")

        tenant_id = (
            self.rag_harness_config.get("tenant_b_id", "tenant-beta")
            if tenant_role in ("secondary", "tenant_b")
            else self.rag_harness_config.get("tenant_a_id", "tenant-alpha")
        )

        payload: dict[str, Any] = {
            self.query_field: prompt,
            "tenant_id": tenant_id,
            "include_retrieval_telemetry": True,
        }
        if system_prompt:
            payload["system_prompt"] = system_prompt
        if context_documents:
            payload["injected_documents"] = context_documents
        if tools:
            payload["tools"] = tools
        if extra_payload:
            payload.update(extra_payload)

        (
            status_code,
            parsed_body,
            resp_headers,
            latency_ms,
            error_type,
            error_message,
            redacted_req,
        ) = await self.client.send_json_request(
            method="POST",
            json_payload=payload,
            custom_headers=self.custom_headers,
            tenant_role=tenant_role,
        )

        output_text = ""
        retrieved_chunks: list[dict[str, Any]] = []
        citations: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        guardrail_blocked = False

        if isinstance(parsed_body, dict):
            for key in ("answer", "response", "output", "text", "result"):
                val = parsed_body.get(key)
                if isinstance(val, str):
                    output_text = val
                    break

            raw_chunks = (
                parsed_body.get("retrieved_chunks")
                or parsed_body.get("chunks")
                or parsed_body.get("source_documents")
            )
            if isinstance(raw_chunks, list):
                retrieved_chunks = [c for c in raw_chunks if isinstance(c, dict)]

            raw_citations = parsed_body.get("citations") or parsed_body.get("sources")
            if isinstance(raw_citations, list):
                citations = [str(c) for c in raw_citations]

            if isinstance(parsed_body.get("tool_calls"), list):
                tool_calls = [t for t in parsed_body["tool_calls"] if isinstance(t, dict)]

            if status_code is not None and self.client._is_guardrail_block(
                status_code, parsed_body
            ):
                guardrail_blocked = True
        elif isinstance(parsed_body, str):
            output_text = parsed_body
            if status_code is not None and self.client._is_guardrail_block(
                status_code, parsed_body
            ):
                guardrail_blocked = True

        return StandardizedTargetResponse(
            status_code=status_code,
            output_text=output_text,
            raw_request=redacted_req,
            raw_response=parsed_body,
            response_headers=resp_headers,
            latency_ms=latency_ms,
            retrieved_chunks=retrieved_chunks,
            citations=citations,
            tool_calls=tool_calls,
            guardrail_blocked=guardrail_blocked,
            error_type=error_type,
            error_message=error_message,
        )
