"""Historical empty-host SSRF fail-open validator regression fixture."""

import ipaddress
import socket
import urllib.parse


def is_safe_url(url: str) -> bool:
    """Preserve the vulnerable validation flow without executing network I/O."""
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    raw = host.split("%", 1)[0].strip("[]")

    def is_bad_ip(ip) -> bool:
        return ip.is_private or ip.is_loopback

    try:
        ip = ipaddress.ip_address(raw)
        if is_bad_ip(ip):
            return False
    except ValueError:
        # Non-literal hostnames continue to the DNS resolution checks below.
        pass

    try:
        resolved = socket.getaddrinfo(raw, None)
        for entry in resolved:
            ip = ipaddress.ip_address(entry[4][0].split("%", 1)[0])
            if is_bad_ip(ip):
                return False
    except socket.gaierror:
        # Historical fail-open path: an empty hostname reaches here and is ignored.
        pass
    except ValueError:
        return False

    return True
