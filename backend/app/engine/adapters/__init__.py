"""Target Adapters package and factory for AegisAI Assessment Engine."""

from typing import Any

import httpx

from app.engine.adapters.base import (
    RequestBudgetExceededError,
    SafeTargetClient,
    TargetAdapter,
    TokenBucketRateLimiter,
)
from app.engine.adapters.generic_rest import GenericRestAdapter
from app.engine.adapters.openai_compat import OpenAICompatibleAdapter
from app.engine.adapters.rag_adapter import RAGHarnessAdapter
from app.engine.adapters.simulator import (
    DEFAULT_SIMULATED_SYSTEM_PROMPT,
    BuiltInTargetSimulator,
)


def create_target_adapter(
    *,
    integration_mode: str,
    endpoint_url: str,
    allowed_hosts: list[str],
    auth_type: str = "NONE",
    decrypted_credentials: dict[str, Any] | None = None,
    request_template: dict[str, Any] | None = None,
    architecture_manifest: dict[str, Any] | None = None,
    rag_harness_config: dict[str, Any] | None = None,
    agent_harness_config: dict[str, Any] | None = None,
    rate_limit_rps: float = 2.0,
    timeout_seconds: int = 15,
    max_total_requests: int | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    resolve_dns: bool = True,
) -> TargetAdapter:
    """Factory that constructs the appropriate TargetAdapter for the target's integration mode."""
    mode = (integration_mode or "SIMULATOR").upper()

    if mode in ("SIMULATOR", "CONFIG_ONLY"):
        return BuiltInTargetSimulator(
            endpoint_url=endpoint_url,
            request_template=request_template,
            architecture_manifest=architecture_manifest,
            rag_harness_config=rag_harness_config,
            agent_harness_config=agent_harness_config,
            max_total_requests=max_total_requests or 200,
        )

    safe_client = SafeTargetClient(
        endpoint_url=endpoint_url,
        allowed_hosts=allowed_hosts,
        auth_type=auth_type,
        decrypted_credentials=decrypted_credentials,
        rate_limit_rps=rate_limit_rps,
        timeout_seconds=timeout_seconds,
        max_total_requests=max_total_requests,
        transport=transport,
        resolve_dns=resolve_dns,
    )

    if mode == "OPENAI_COMPAT":
        return OpenAICompatibleAdapter(
            client=safe_client,
            request_template=request_template,
        )
    if mode == "ASSISTED_HARNESS":
        return RAGHarnessAdapter(
            client=safe_client,
            request_template=request_template,
            rag_harness_config=rag_harness_config,
        )
    return GenericRestAdapter(
        client=safe_client,
        request_template=request_template,
    )


__all__ = [
    "BuiltInTargetSimulator",
    "DEFAULT_SIMULATED_SYSTEM_PROMPT",
    "GenericRestAdapter",
    "OpenAICompatibleAdapter",
    "RAGHarnessAdapter",
    "RequestBudgetExceededError",
    "SafeTargetClient",
    "TargetAdapter",
    "TokenBucketRateLimiter",
    "create_target_adapter",
]
