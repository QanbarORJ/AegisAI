"""Multi-Layer SSRF Defense & Network Boundary Validator.

Implements SECURITY_DESIGN.md Section 3 and mitigates TM-01:
1. Strict URL parsing (HTTP/HTTPS only; rejects embedded user:pass credentials).
2. Explicit allowlist host validation against TargetProfile.allowed_hosts.
3. Pre-connect DNS resolution via socket.getaddrinfo.
4. IPv4 and IPv6 CIDR validation blocking loopback, RFC 1918 private, link-local
   (169.254.0.0/16 including AWS/GCP/Azure IMDS 169.254.169.254), multicast,
   reserved, unspecified, and Carrier-Grade NAT (100.64.0.0/10).
5. Isolated local sandbox mode override that still unconditionally blocks cloud
   metadata endpoints (169.254.169.254 / fd00:ec2::254).
"""

import ipaddress
import socket
from collections.abc import Sequence
from urllib.parse import urlparse

from app.core.config import get_settings
from app.core.exceptions import ScopeViolationError, SSRFBlockedError

# Unconditionally prohibited cloud metadata IPs and networks (even in local sandbox mode)
_CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),      # AWS / GCP / Azure / DigitalOcean link-local IMDS
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud IMDS
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 IMDS
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-Local
]

# Carrier-Grade NAT (RFC 6598)
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def validate_ip_address(
    ip_str: str,
    *,
    allow_isolated_local: bool = False,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate a single IPv4 or IPv6 address against SSRF prohibited ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise SSRFBlockedError(
            f"Invalid IP address format '{ip_str}'.", blocked_target=ip_str
        ) from exc

    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:169.254.169.254 or ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    # 1. Unconditional block on Cloud Metadata & Link-Local (NEVER allowed even in local dev)
    for net in _CLOUD_METADATA_NETWORKS:
        if ip_obj in net:
            raise SSRFBlockedError(
                f"Access to link-local / cloud metadata address '{ip_obj}' is unconditionally prohibited.",
                blocked_target=str(ip_obj),
            )

    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        raise SSRFBlockedError(
            f"Access to non-routable / reserved address '{ip_obj}' is prohibited.",
            blocked_target=str(ip_obj),
        )

    # 2. Check Loopback / Private / Reserved / CGNAT
    is_cgnat = isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NETWORK
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved or is_cgnat:
        if not allow_isolated_local:
            raise SSRFBlockedError(
                f"SSRF Protection: Target resolved to restricted private/loopback IP '{ip_obj}'.",
                blocked_target=str(ip_obj),
            )

    return ip_obj


def validate_target_url(
    url: str,
    *,
    allowed_hosts: Sequence[str] | None = None,
    resolve_dns: bool = True,
    allow_isolated_local_override: bool | None = None,
) -> dict[str, object]:
    """Validate a target URL for scheme safety, scope allowlist membership, and SSRF IP safety.

    Returns a dictionary with parsed hostname, port, scheme, and validated resolved IPs.
    """
    if not url or not isinstance(url, str):
        raise SSRFBlockedError("Target URL must be a non-empty string.")

    parsed = urlparse(url.strip())

    # 1. Scheme check
    if parsed.scheme not in ("https", "http"):
        raise SSRFBlockedError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.",
            blocked_target=url,
        )

    # 2. Reject embedded credentials (http://user:pass@host)
    if parsed.username or parsed.password:
        raise SSRFBlockedError(
            "Embedded credentials in target URLs are prohibited.",
            blocked_target=url,
        )

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFBlockedError("Target URL is missing a valid hostname.", blocked_target=url)

    # 3. Check explicit Scope Allowlist if provided
    if allowed_hosts is not None:
        normalized_allowlist = {h.strip().lower() for h in allowed_hosts if h.strip()}
        if hostname not in normalized_allowlist:
            raise ScopeViolationError(
                f"Target host '{hostname}' is not in the authorized scope allowlist: {sorted(normalized_allowlist)}"
            )

    settings = get_settings()
    allow_local = (
        allow_isolated_local_override
        if allow_isolated_local_override is not None
        else (
            settings.aegis_allow_isolated_local_targets
            and hostname in settings.allowed_local_hosts_set
        )
    )

    # 4. If hostname is a literal IP address, validate it directly
    try:
        ip_literal = ipaddress.ip_address(hostname)
        validate_ip_address(str(ip_literal), allow_isolated_local=allow_local)
        return {
            "scheme": parsed.scheme,
            "hostname": hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "resolved_ips": [str(ip_literal)],
        }
    except ValueError:
        pass

    # Block well-known metadata hostnames before DNS lookup
    if hostname in {
        "metadata.google.internal",
        "metadata",
        "instance-data",
        "169.254.169.254.nip.io",
    }:
        raise SSRFBlockedError(
            f"Access to cloud metadata hostname '{hostname}' is unconditionally prohibited.",
            blocked_target=hostname,
        )

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolved_ips: list[str] = []

    if resolve_dns:
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SSRFBlockedError(
                f"Unable to resolve target hostname '{hostname}': {exc}",
                blocked_target=hostname,
            ) from exc

        for family, _, _, _, sockaddr in addr_info:
            if family in (socket.AF_INET, socket.AF_INET6):
                ip_str = str(sockaddr[0])
                validated = validate_ip_address(ip_str, allow_isolated_local=allow_local)
                if str(validated) not in resolved_ips:
                    resolved_ips.append(str(validated))

        if not resolved_ips:
            raise SSRFBlockedError(
                f"Hostname '{hostname}' did not resolve to any valid IPv4/IPv6 addresses.",
                blocked_target=hostname,
            )

    return {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "resolved_ips": resolved_ips,
    }
