"""OpenAI-Compatible Chat/Completions Target Adapter.

Supports standard `/v1/chat/completions` endpoints (OpenAI, Azure OpenAI, vLLM, LiteLLM, Ollama, custom proxies).
"""

from typing import Any

from app.engine.adapters.base import SafeTargetClient, TargetAdapter
from app.engine.contracts import StandardizedTargetResponse


class OpenAICompatibleAdapter(TargetAdapter):
    """Adapter for OpenAI-compatible `/v1/chat/completions` JSON schemas."""

    def __init__(
        self,
        client: SafeTargetClient,
        *,
        request_template: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(client=client)
        self.request_template = request_template or {}
        self.model_name = str(self.request_template.get("model") or "gpt-4o-mini")
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
            raise RuntimeError("OpenAICompatibleAdapter requires a configured SafeTargetClient.")

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        if context_documents:
            joined_ctx = "\n\n---\n\n".join(context_documents)
            messages.append(
                {
                    "role": "system",
                    "content": f"Retrieved Context Documents:\n{joined_ctx}",
                }
            )
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
        }
        if "temperature" in self.request_template:
            payload["temperature"] = self.request_template["temperature"]
        if "max_tokens" in self.request_template:
            payload["max_tokens"] = self.request_template["max_tokens"]
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
        tool_calls: list[dict[str, Any]] = []
        retrieved_chunks: list[dict[str, Any]] = []
        citations: list[str] = []
        guardrail_blocked = False

        if isinstance(parsed_body, dict):
            choices = parsed_body.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0] if isinstance(choices[0], dict) else {}
                finish_reason = str(first.get("finish_reason") or "").lower()
                if finish_reason == "content_filter":
                    guardrail_blocked = True

                msg = first.get("message")
                if isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, str):
                        output_text = content
                    raw_tools = msg.get("tool_calls")
                    if isinstance(raw_tools, list):
                        tool_calls = [t for t in raw_tools if isinstance(t, dict)]
                elif isinstance(first.get("text"), str):
                    output_text = str(first["text"])

            if not output_text and isinstance(parsed_body.get("output"), str):
                output_text = str(parsed_body["output"])

            if isinstance(parsed_body.get("retrieved_chunks"), list):
                retrieved_chunks = [
                    c for c in parsed_body["retrieved_chunks"] if isinstance(c, dict)
                ]
            if isinstance(parsed_body.get("citations"), list):
                citations = [str(c) for c in parsed_body["citations"]]

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
