"""Phase 2 Verification: Multi-Layer SSRF Guard & Scope Boundary Enforcement (SECURITY_DESIGN.md Section 3)."""

import socket

import pytest

from app.core.exceptions import ScopeViolationError, SSRFBlockedError
from app.core.ssrf_guard import validate_ip_address, validate_target_url


@pytest.mark.parametrize(
    "blocked_ip",
    [
        "127.0.0.1",
        "127.0.1.1",
        "::1",
        "::ffff:127.0.0.1",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.100.50",
        "100.64.0.1",        # CGNAT (RFC 6598)
        "169.254.169.254",   # AWS/GCP/Azure IMDS
        "::ffff:169.254.169.254",
        "100.100.100.200",   # Alibaba Cloud IMDS
        "fd00:ec2::254",     # AWS IPv6 IMDS
        "fe80::1",           # IPv6 Link-Local
        "0.0.0.0",           # Unspecified
        "224.0.0.1",         # Multicast
    ],
)
def test_ssrf_guard_blocks_loopback_private_and_metadata_ips(blocked_ip: str) -> None:
    """Verify validate_ip_address rejects loopback, RFC 1918 private, CGNAT, and cloud metadata IPs."""
    with pytest.raises(SSRFBlockedError):
        validate_ip_address(blocked_ip, allow_isolated_local=False)


@pytest.mark.parametrize(
    "metadata_ip",
    [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
        "fe80::1",
    ],
)
def test_cloud_metadata_ips_remain_blocked_even_in_isolated_local_mode(
    metadata_ip: str,
) -> None:
    """Cloud metadata IPs (169.254.169.254) must NEVER be allowed even when allow_isolated_local=True."""
    with pytest.raises(SSRFBlockedError):
        validate_ip_address(metadata_ip, allow_isolated_local=True)


def test_isolated_local_mode_allows_loopback_only_when_explicitly_enabled() -> None:
    """Loopback (127.0.0.1) is permitted only when allow_isolated_local=True."""
    ip_obj = validate_ip_address("127.0.0.1", allow_isolated_local=True)
    assert str(ip_obj) == "127.0.0.1"


def test_validate_target_url_rejects_non_http_schemes_and_embedded_credentials() -> None:
    """Reject file://, gopher://, ftp:// and URLs containing user:pass@host."""
    with pytest.raises(SSRFBlockedError):
        validate_target_url("file:///etc/passwd", resolve_dns=False)

    with pytest.raises(SSRFBlockedError):
        validate_target_url("gopher://example.com:70/1", resolve_dns=False)

    with pytest.raises(SSRFBlockedError):
        validate_target_url(
            "https://admin:secretpassword@api.customer.example/v1/chat",
            resolve_dns=False,
        )


def test_validate_target_url_enforces_scope_allowlist() -> None:
    """Reject URLs whose hostname is not in the authorized TargetProfile.allowed_hosts."""
    with pytest.raises(ScopeViolationError):
        validate_target_url(
            "https://unauthorized.attacker.example/v1/chat",
            allowed_hosts=["api.customer.example"],
            resolve_dns=False,
        )


def test_validate_target_url_blocks_literal_private_and_metadata_urls() -> None:
    """Literal IP URLs pointing to 127.0.0.1, 10.x.x.x, or 169.254.169.254 must be blocked."""
    for url, host in [
        ("http://127.0.0.1:8000/v1/chat", "127.0.0.1"),
        ("http://10.0.0.42/v1/chat", "10.0.0.42"),
        ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
        ("http://metadata.google.internal/computeMetadata/v1/", "metadata.google.internal"),
    ]:
        with pytest.raises(SSRFBlockedError):
            validate_target_url(url, allowed_hosts=[host], resolve_dns=False)


def test_validate_target_url_preconnect_dns_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify pre-connect DNS resolution blocks domains resolving to private/metadata IPs and allows public IPs."""

    def _mock_getaddrinfo_rebinding(host: str, port: int, type: int = 0):
        if host == "rebind-metadata.attacker.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        if host == "rebind-internal.attacker.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.12.34.56", port))]
        if host == "api.customer.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo_rebinding)

    # DNS resolving to 169.254.169.254 -> Blocked
    with pytest.raises(SSRFBlockedError):
        validate_target_url(
            "https://rebind-metadata.attacker.example/v1/chat",
            allowed_hosts=["rebind-metadata.attacker.example"],
            resolve_dns=True,
        )

    # DNS resolving to 10.12.34.56 -> Blocked
    with pytest.raises(SSRFBlockedError):
        validate_target_url(
            "https://rebind-internal.attacker.example/v1/chat",
            allowed_hosts=["rebind-internal.attacker.example"],
            resolve_dns=True,
        )

    # DNS resolving to public IP 93.184.216.34 -> Allowed
    result = validate_target_url(
        "https://api.customer.example/v1/chat",
        allowed_hosts=["api.customer.example"],
        resolve_dns=True,
    )
    assert result["hostname"] == "api.customer.example"
    assert result["port"] == 443
    assert result["resolved_ips"] == ["93.184.216.34"]
