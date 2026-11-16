"""Target Profiler & Connectivity Verifier (`TargetProfiler`).

Implements ARCHITECTURE.md Section 4.1 (State 3: PROFILING) and ROADMAP.md Phase 3:
- Validates SSRF/DNS safety and scope allowlist binding.
- Sends a benign baseline readiness probe through the configured TargetAdapter.
- Measures baseline latency, checks authentication validity, and detects response telemetry capabilities.
"""

from collections.abc import Sequence

from app.core.exceptions import ScopeViolationError, SSRFBlockedError
from app.core.ssrf_guard import validate_target_url
from app.engine.adapters.base import TargetAdapter
from app.engine.contracts import TargetProfileResult


class TargetProfiler:
    """Profiles a target endpoint prior to active security test execution."""

    BASELINE_PING_PROMPT = "Hello. Please confirm assistant service readiness with a brief greeting."

    async def profile_target(
        self,
        *,
        endpoint_url: str,
        allowed_hosts: Sequence[str],
        integration_mode: str,
        adapter: TargetAdapter,
        resolve_dns: bool | None = None,
    ) -> TargetProfileResult:
        """Validate SSRF boundaries and execute a baseline connectivity/capability check."""
        mode = (integration_mode or "SIMULATOR").upper()
        should_resolve_dns = (
            resolve_dns
            if resolve_dns is not None
            else (mode not in ("SIMULATOR", "CONFIG_ONLY"))
        )

        # 1. Validate URL scheme, allowed_hosts scope, and SSRF IP safety
        try:
            url_info = validate_target_url(
                endpoint_url,
                allowed_hosts=allowed_hosts,
                resolve_dns=should_resolve_dns,
            )
            resolved_ips = [str(ip) for ip in url_info.get("resolved_ips", [])]  # type: ignore[union-attr]
        except (SSRFBlockedError, ScopeViolationError) as exc:
            return TargetProfileResult(
                reachable=False,
                auth_verified=False,
                error_reason=f"{exc.code}: {exc.message}",
            )

        # 2. Static manifest-only mode does not require active network probing
        if mode == "CONFIG_ONLY":
            return TargetProfileResult(
                reachable=True,
                status_code=200,
                baseline_latency_ms=0.0,
                auth_verified=True,
                detected_capabilities=["CONFIG_ONLY"],
                ssrf_validated_ips=resolved_ips,
            )

        # 3. Send benign baseline ping
        resp = await adapter.send_prompt(self.BASELINE_PING_PROMPT)

        if resp.is_transport_error or resp.error_type == "AUTH_OR_PERMISSION_ERROR":
            return TargetProfileResult(
                reachable=False,
                status_code=resp.status_code,
                baseline_latency_ms=round(resp.latency_ms, 2),
                auth_verified=resp.error_type != "AUTH_OR_PERMISSION_ERROR",
                ssrf_validated_ips=resolved_ips,
                error_reason=resp.error_message or f"Target profiling failed ({resp.error_type})",
            )

        capabilities: list[str] = ["CHAT_COMPLETION"]
        if resp.retrieved_chunks:
            capabilities.append("RETRIEVAL_CHUNKS")
        if resp.citations:
            capabilities.append("CITATIONS")
        if resp.tool_calls:
            capabilities.append("TOOL_CALLS")

        return TargetProfileResult(
            reachable=True,
            status_code=resp.status_code,
            baseline_latency_ms=round(resp.latency_ms, 2),
            auth_verified=True,
            detected_capabilities=capabilities,
            guardrail_detected=resp.guardrail_blocked,
            guardrail_signature="BASELINE_GUARDRAIL_ACTIVE" if resp.guardrail_blocked else None,
            ssrf_validated_ips=resolved_ips,
        )
