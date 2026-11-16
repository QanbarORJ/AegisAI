"""Configurable JSON-path Generic REST Endpoint Target Adapter."""

from typing import Any

from app.engine.adapters.base import SafeTargetClient, TargetAdapter
from app.engine.contracts import StandardizedTargetResponse


def _extract_dotted_path(data: Any, path: str) -> Any:
    """Resolve a simple dot-notation path (e.g. 'data.result.answer') on nested dicts/lists."""
    if not path:
        return None
    current = data
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit():
            idx = int(segment)
            if 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
        else:
            return None
    return current


def _set_dotted_path(target: dict[str, Any], path: str, value: Any) -> None:
    """Set a value inside a dictionary using dot-notation (e.g., 'input.query')."""
    parts = [p for p in path.split(".") if p]
    if not parts:
        target["prompt"] = value
        return
    curr = target
    for part in parts[:-1]:
        if part not in curr or not isinstance(curr[part], dict):
            curr[part] = {}
        curr = curr[part]
    curr[parts[-1]] = value


class GenericRestAdapter(TargetAdapter):
    """Adapter for custom REST endpoints using configurable prompt and response field paths."""

    def __init__(
        self,
        client: SafeTargetClient,
        *,
        request_template: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(client=client)
        self.request_template = request_template or {}
        self.prompt_field = str(self.request_template.get("prompt_field") or "prompt")
        self.response_field = str(self.request_template.get("response_field") or "")
        self.static_fields = (
            dict(self.request_template["static_fields"])
            if isinstance(self.request_template.get("static_fields"), dict)
            else {}
        )
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
            raise RuntimeError("GenericRestAdapter requires a configured SafeTargetClient.")

        payload: dict[str, Any] = dict(self.static_fields)
        _set_dotted_path(payload, self.prompt_field, prompt)

        if system_prompt:
            payload["system_prompt"] = system_prompt
        if context_documents:
            payload["context_documents"] = context_documents
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
            if self.response_field:
                extracted = _extract_dotted_path(parsed_body, self.response_field)
                if extracted is not None:
                    output_text = str(extracted)

            if not output_text:
                for candidate_key in ("response", "answer", "output", "text", "result", "message"):
                    val = parsed_body.get(candidate_key)
                    if isinstance(val, str):
                        output_text = val
                        break

            if isinstance(parsed_body.get("retrieved_chunks"), list):
                retrieved_chunks = [
                    c for c in parsed_body["retrieved_chunks"] if isinstance(c, dict)
                ]
            if isinstance(parsed_body.get("citations"), list):
                citations = [str(c) for c in parsed_body["citations"]]
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
