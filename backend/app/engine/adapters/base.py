"""Base TargetAdapter interface, Token-Bucket Rate Limiter, and SSRF-Safe HTTP Client.

Implements ARCHITECTURE.md Section 2 & 4.3, SECURITY_DESIGN.md Section 2 & 3, and THREAT_MODEL.md TM-01, TM-05, TM-06, TM-08.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.exceptions import ScopeViolationError, SSRFBlockedError
from app.core.ssrf_guard import validate_target_url
from app.engine.contracts import StandardizedTargetResponse
from app.engine.evidence import redact_headers, sanitize_payload


class TokenBucketRateLimiter:
    """Asynchronous token-bucket rate limiter enforcing max requests per second (RPS)."""

    def __init__(self, rate_rps: float, capacity: float | None = None) -> None:
        self.rate_rps = max(0.1, float(rate_rps))
        self.capacity = max(1.0, float(capacity if capacity is not None else self.rate_rps))
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available and consume one token."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_rps)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            wait_time = (1.0 - self._tokens) / self.rate_rps
            self._tokens = 0.0
            await asyncio.sleep(wait_time)
            self._last_refill = time.monotonic()


class RequestBudgetExceededError(Exception):
    """Raised when an assessment exceeds its hard ceiling on outbound probes."""


class SafeTargetClient:
    """SSRF-guarded, rate-limited, redirect-blocking, size-capped async HTTP client for target probes."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        allowed_hosts: Sequence[str],
        auth_type: str = "NONE",
        decrypted_credentials: dict[str, Any] | None = None,
        rate_limit_rps: float | None = None,
        timeout_seconds: int | None = None,
        max_response_bytes: int | None = None,
        max_total_requests: int | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        resolve_dns: bool = True,
    ) -> None:
        settings = get_settings()
        self.endpoint_url = endpoint_url.strip()
        self.allowed_hosts = [h.strip().lower() for h in allowed_hosts if h and h.strip()]
        self.auth_type = (auth_type or "NONE").upper()
        self._credentials = decrypted_credentials or {}
        self.rate_limiter = TokenBucketRateLimiter(
            rate_rps=rate_limit_rps or settings.aegis_default_max_rps
        )
        self.timeout_seconds = timeout_seconds or settings.aegis_default_request_timeout_seconds
        self.max_response_bytes = max_response_bytes or settings.aegis_max_response_bytes
        self.max_total_requests = (
            max_total_requests or settings.aegis_max_requests_per_assessment
        )
        self.resolve_dns = resolve_dns
        self.requests_sent = 0
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout_seconds),
            transport=transport,
        )

    def _build_auth_headers(
        self,
        tenant_role: str = "primary",
        custom_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Inject decrypted target credentials into outbound headers at dispatch time only."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if custom_headers:
            for k, v in custom_headers.items():
                headers[str(k)] = str(v)

        if self.auth_type == "BEARER_TOKEN":
            token = (
                self._credentials.get("bearer_token")
                or self._credentials.get("api_key")
                or ""
            )
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif self.auth_type == "API_KEY_HEADER":
            header_name = str(self._credentials.get("header_name") or "X-API-Key")
            api_key = (
                self._credentials.get("api_key")
                or self._credentials.get("bearer_token")
                or ""
            )
            if api_key:
                headers[header_name] = str(api_key)
        elif self.auth_type == "DUAL_TENANT_BEARER":
            if tenant_role == "secondary" or tenant_role == "tenant_b":
                token = (
                    self._credentials.get("tenant_b_token")
                    or self._credentials.get("secondary_token")
                    or ""
                )
            else:
                token = (
                    self._credentials.get("tenant_a_token")
                    or self._credentials.get("primary_token")
                    or self._credentials.get("bearer_token")
                    or ""
                )
            if token:
                headers["Authorization"] = f"Bearer {token}"

        return headers

    async def send_json_request(
        self,
        *,
        method: str = "POST",
        url: str | None = None,
        json_payload: dict[str, Any],
        custom_headers: dict[str, str] | None = None,
        tenant_role: str = "primary",
    ) -> tuple[int | None, dict[str, Any] | str, dict[str, str], float, str | None, str | None, dict[str, Any]]:
        """Execute an SSRF-checked, rate-limited HTTP request with streaming byte cap.

        Returns:
            (status_code, parsed_body, redacted_resp_headers, latency_ms, error_type, error_message, redacted_req_envelope)
        """
        target_url = (url or self.endpoint_url).strip()

        # 1. Pre-connect SSRF & Scope Allowlist verification
        validate_target_url(
            target_url,
            allowed_hosts=self.allowed_hosts,
            resolve_dns=self.resolve_dns,
        )

        # 2. Check execution budget ceiling
        if self.requests_sent >= self.max_total_requests:
            raise RequestBudgetExceededError(
                f"Assessment exceeded maximum request budget ({self.max_total_requests} requests)."
            )

        # 3. Acquire token from rate limiter
        await self.rate_limiter.acquire()
        self.requests_sent += 1

        dispatch_headers = self._build_auth_headers(
            tenant_role=tenant_role, custom_headers=custom_headers
        )
        redacted_request_envelope: dict[str, Any] = {
            "method": method.upper(),
            "url": target_url,
            "headers": redact_headers(dispatch_headers),
            "json": sanitize_payload(json_payload),
        }

        start = time.perf_counter()
        try:
            req = self._client.build_request(
                method=method.upper(),
                url=target_url,
                headers=dispatch_headers,
                json=json_payload,
            )
            resp = await self._client.send(req, stream=True)
            try:
                # 4. Block redirects (DNS rebinding / SSRF pivot protection)
                if resp.status_code in (301, 302, 303, 307, 308):
                    latency = (time.perf_counter() - start) * 1000.0
                    location = resp.headers.get("location", "unknown")
                    await resp.aclose()
                    return (
                        resp.status_code,
                        {"error": f"Redirect to '{location}' blocked by SSRF policy."},
                        redact_headers(dict(resp.headers)),
                        latency,
                        "REDIRECT_BLOCKED",
                        f"HTTP {resp.status_code} redirect to '{location}' was blocked.",
                        redacted_request_envelope,
                    )

                # 5. Enforce streaming response byte ceiling (TM-08 mitigation)
                chunks: list[bytes] = []
                bytes_read = 0
                truncated = False
                async for chunk in resp.aiter_bytes():
                    if bytes_read + len(chunk) > self.max_response_bytes:
                        remaining = self.max_response_bytes - bytes_read
                        if remaining > 0:
                            chunks.append(chunk[:remaining])
                        truncated = True
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)

                raw_bytes = b"".join(chunks)
            finally:
                await resp.aclose()

            latency = (time.perf_counter() - start) * 1000.0
            resp_headers_redacted = redact_headers(dict(resp.headers))
            text_body = raw_bytes.decode("utf-8", errors="replace")
            if truncated:
                text_body += "\n...[TRUNCATED_AT_MAX_RESPONSE_BYTES]"

            parsed_body: dict[str, Any] | str
            try:
                loaded = json.loads(text_body)
                parsed_body = loaded if isinstance(loaded, dict) else {"data": loaded}
            except ValueError:
                parsed_body = text_body

            # 6. Classify transport/server status errors (NEVER treat 5xx/429 as PASS)
            error_type: str | None = None
            error_message: str | None = None
            if resp.status_code == 429:
                error_type = "RATE_LIMITED"
                error_message = "Target returned HTTP 429 Too Many Requests."
            elif resp.status_code >= 500:
                error_type = "HTTP_5XX"
                error_message = f"Target returned server error HTTP {resp.status_code}."
            elif resp.status_code in (401, 403) and not self._is_guardrail_block(
                resp.status_code, parsed_body
            ):
                error_type = "AUTH_OR_PERMISSION_ERROR"
                error_message = f"Target returned HTTP {resp.status_code} authentication/authorization error."

            return (
                resp.status_code,
                parsed_body,
                resp_headers_redacted,
                latency,
                error_type,
                error_message,
                redacted_request_envelope,
            )

        except httpx.TimeoutException as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return (
                None,
                {"error": "Request timed out"},
                {},
                latency,
                "TIMEOUT",
                f"Target request timed out after {self.timeout_seconds}s: {exc}",
                redacted_request_envelope,
            )
        except (SSRFBlockedError, ScopeViolationError):
            raise
        except httpx.RequestError as exc:
            latency = (time.perf_counter() - start) * 1000.0
            return (
                None,
                {"error": str(exc)},
                {},
                latency,
                "NETWORK_ERROR",
                f"Network transport error communicating with target: {exc}",
                redacted_request_envelope,
            )

    @staticmethod
    def _is_guardrail_block(status_code: int, body: dict[str, Any] | str) -> bool:
        """Detect explicit AI guardrail / content filter interception payloads."""
        if status_code not in (200, 400, 403, 422):
            return False
        text = json.dumps(body).lower() if isinstance(body, dict) else str(body).lower()
        guardrail_markers = (
            "guardrail",
            "content_filter",
            "content_policy_violation",
            "prompt_shield",
            "safety_system",
            "blocked by security policy",
            "aegis_guardrail_blocked",
        )
        return any(marker in text for marker in guardrail_markers)

    async def close(self) -> None:
        """Close the underlying async HTTP client."""
        await self._client.aclose()


class TargetAdapter(ABC):
    """Uniform adapter interface hiding target-specific API schemas from security test plugins."""

    def __init__(self, client: SafeTargetClient | None = None) -> None:
        self.client = client

    @property
    def total_probes_sent(self) -> int:
        return self.client.requests_sent if self.client else 0

    @abstractmethod
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
        """Send a security test prompt/payload to the target and return a StandardizedTargetResponse."""
        raise NotImplementedError

    async def close(self) -> None:
        """Release any underlying network connections."""
        if self.client is not None:
            await self.client.close()
