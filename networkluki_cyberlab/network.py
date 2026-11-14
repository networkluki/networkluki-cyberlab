"""Bounded, explicit-target network observations; no exploit execution."""

from __future__ import annotations

import concurrent.futures
import http.client
import io
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
from urllib.parse import quote, urlsplit, urlunsplit


MAX_PORTS = 128
CONNECT_TIMEOUT = 0.6
WEB_TIMEOUT = 8.0
MAX_HEADER_BYTES = 65536


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise RuntimeError("Operation cancelled")


def parse_ports(text: str) -> list[int]:
    """Parse comma-separated ports/ranges with a strict 128-port ceiling."""
    if not isinstance(text, str) or not text or len(text) > 2048:
        raise ValueError("Enter 1 to 128 TCP ports, for example 22,80,443.")
    ports: set[int] = set()
    for item in text.split(","):
        item = item.strip()
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            raise ValueError("Ports must be numbers or ascending ranges separated by commas.")
        bounds = [int(value) for value in item.split("-")]
        first, last = bounds[0], bounds[-1]
        if not 1 <= first <= last <= 65535:
            raise ValueError("TCP ports must be between 1 and 65535; ranges must ascend.")
        if last - first + 1 > MAX_PORTS:
            raise ValueError("A job may check at most 128 TCP ports.")
        ports.update(range(first, last + 1))
        if len(ports) > MAX_PORTS:
            raise ValueError("A job may check at most 128 TCP ports.")
    return sorted(ports)


def _validated_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        raise ValueError("Enter one explicit IPv4 or IPv6 address without a zone ID.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Enter one explicit IPv4 or IPv6 address; hostnames and subnets are not accepted here.") from exc
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else address
    effective = effective or address
    if effective.is_unspecified or effective.is_multicast or str(effective) == "255.255.255.255":
        raise ValueError("Unspecified, multicast and limited-broadcast addresses are not accepted.")
    return address


def tcp_scan(target: str, ports: str, cancel: threading.Event | None = None) -> dict:
    """Perform ordinary TCP connections against one IP, without privilege escalation."""
    _check_cancel(cancel)
    address = _validated_ip(target)
    parsed_ports = parse_ports(ports)
    started = time.monotonic()
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET

    def check_port(port: int) -> dict:
        _check_cancel(cancel)
        attempt_start = time.monotonic()
        error = None
        try:
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(CONNECT_TIMEOUT)
                code = connection.connect_ex((str(address), port))
                is_open = code == 0
                if code:
                    error = f"Connection not established (OS error {code})."
        except OSError as exc:
            is_open = False
            error = str(exc)
        _check_cancel(cancel)
        return {
            "port": port,
            "state": "open" if is_open else "closed_or_filtered",
            "duration_ms": round((time.monotonic() - attempt_start) * 1000, 1),
            "detail": error or "A TCP connection was established; the service was not identified.",
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(parsed_ports))) as pool:
        results = list(pool.map(check_port, parsed_ports))
    _check_cancel(cancel)
    return {
        "module": "network",
        "target": str(address),
        "method": "TCP connect",
        "ports": results,
        "open_count": sum(item["state"] == "open" for item in results),
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "notes": [
            "A failed connection does not distinguish closed, filtered, unreachable or local connection errors.",
            "Open ports alone are not evidence of a vulnerability.",
        ],
    }


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("The HTTP/TLS observation exceeded its 8-second time limit.")
    return remaining


def _resolve(host: str, port: int, deadline: float, cancel: threading.Event | None) -> list[str]:
    """Resolve once, validate all returned addresses and return pinned candidates."""
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError:
        numeric = None
    if numeric is not None:
        return [str(_validated_ip(str(numeric)))]
    result_queue: queue.Queue = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            result_queue.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as exc:
            result_queue.put(exc)

    # OS DNS calls cannot be interrupted portably. A daemon thread bounds the caller's
    # wait; a cancelled/expired resolver may finish in the background, with no connect.
    threading.Thread(target=lookup, name="cyberlab-dns", daemon=True).start()
    while True:
        _check_cancel(cancel)
        try:
            result = result_queue.get(timeout=min(0.1, _remaining(deadline)))
            break
        except queue.Empty:
            continue
    if isinstance(result, Exception):
        raise OSError(f"DNS resolution failed: {result}") from result
    addresses = []
    for family, _, _, _, socket_address in result:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(_validated_ip(socket_address[0]))
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError("DNS returned no supported unicast IP addresses.")
    return addresses


def _parse_url(url: str) -> tuple[str, str, int, str, str, str]:
    if not isinstance(url, str) or len(url) > 4096 or not url:
        raise ValueError("Enter an HTTP or HTTPS URL no longer than 4096 characters.")
    if any(ord(character) <= 32 or ord(character) == 127 for character in url):
        raise ValueError("URLs must not contain spaces or control characters; percent-encode the path.")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL hostname or port is invalid.") from exc
    if parsed.scheme not in ("http", "https") or not host:
        raise ValueError("Only HTTP and HTTPS URLs with an explicit hostname are accepted.")
    if parsed.username is not None or parsed.password is not None or "#" in url:
        raise ValueError("Credentials and fragments are not accepted in URLs.")
    if "%" in host:
        raise ValueError("Percent-encoded hostnames and IPv6 zone IDs are not accepted.")
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError:
        numeric = None
    if numeric is not None:
        host = str(_validated_ip(str(numeric)))
        host_header = f"[{host}]" if numeric.version == 6 else host
    else:
        try:
            host = host.removesuffix(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("The hostname cannot be encoded as IDNA.") from exc
        labels = host.split(".")
        if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("The URL contains an invalid DNS hostname.")
        host_header = host
    default_port = 443 if parsed.scheme == "https" else 80
    port = default_port if port is None else port
    if not 1 <= port <= 65535:
        raise ValueError("The URL port must be between 1 and 65535.")
    if port != default_port:
        host_header += f":{port}"
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~[]")
    request_target = path + ("?" + query if query else "")
    normalized_url = urlunsplit((parsed.scheme, host_header, path, query, ""))
    return parsed.scheme, host, port, host_header, request_target, normalized_url


def _read_headers(connection: socket.socket, deadline: float, cancel: threading.Event | None) -> tuple[int, str, http.client.HTTPMessage]:
    received = bytearray()
    total = 0
    interim_responses = 0
    while True:
        _check_cancel(cancel)
        boundary = received.find(b"\r\n\r\n")
        if boundary != -1:
            block = bytes(received[: boundary + 4])
            del received[: boundary + 4]
            first_line, rest = block.split(b"\r\n", 1)
            match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \t]([^\r\n]*))?", first_line)
            if match is None:
                raise OSError("The peer did not return a supported HTTP/1.x status line.")
            status = int(match.group(1))
            reason = (match.group(2) or b"").decode("iso-8859-1")
            headers = http.client.parse_headers(io.BytesIO(rest))
            if 100 <= status < 200 and status != 101:
                interim_responses += 1
                if interim_responses > 4:
                    raise OSError("Too many interim HTTP responses.")
                continue
            return status, reason, headers
        connection.settimeout(min(0.25, _remaining(deadline)))
        try:
            part = connection.recv(min(4096, MAX_HEADER_BYTES - total + 1))
        except socket.timeout:
            continue
        if not part:
            raise OSError("The peer closed the connection before sending complete HTTP headers.")
        total += len(part)
        if total > MAX_HEADER_BYTES:
            raise OSError("HTTP response headers exceed the 64 KiB limit.")
        received.extend(part)


def _redact_result_url(value: str) -> str:
    """Remove URL authority credentials, query data and fragments from stored results."""
    try:
        parsed = urlsplit(value)
        # Fail closed for ambiguous credential-like relative URLs.
        if not parsed.netloc and "@" in parsed.path:
            return "[redacted URL]"
        return urlunsplit((
            parsed.scheme,
            parsed.netloc.rsplit("@", 1)[-1],
            parsed.path,
            "[redacted]" if parsed.query else "",
            "[redacted]" if parsed.fragment else "",
        ))
    except ValueError:
        return "[redacted URL]"


def web_probe(url: str, cancel: threading.Event | None = None) -> dict:
    """Send one HEAD request, with DNS pinning and normal HTTPS verification."""
    _check_cancel(cancel)
    scheme, host, port, host_header, request_target, normalized_url = _parse_url(url)
    started = time.monotonic()
    deadline = started + WEB_TIMEOUT
    addresses = _resolve(host, port, deadline, cancel)
    selected_ip = addresses[0]
    address = ipaddress.ip_address(selected_ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    tls = None
    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        _check_cancel(cancel)
        connection.settimeout(_remaining(deadline))
        connection.connect((selected_ip, port))
        if scheme == "https":
            context = ssl.create_default_context()
            connection.settimeout(_remaining(deadline))
            connection = context.wrap_socket(connection, server_hostname=host)
            certificate = connection.getpeercert()
            tls = {
                "verified": True,
                "version": connection.version(),
                "cipher": connection.cipher()[0] if connection.cipher() else None,
                "certificate_not_before": certificate.get("notBefore"),
                "certificate_not_after": certificate.get("notAfter"),
                "hostname_checked": host,
            }
        _check_cancel(cancel)
        request = (
            f"HEAD {request_target} HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: NetworkLuki-CyberLab/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        connection.settimeout(_remaining(deadline))
        connection.sendall(request)
        status, reason, raw_headers = _read_headers(connection, deadline, cancel)
    finally:
        connection.close()
    _check_cancel(cancel)
    redact = {"set-cookie", "set-cookie2", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
    headers = [
        {
            "name": name,
            "value": "[redacted]" if name.lower() in redact else (
                _redact_result_url(value) if name.lower() in {"location", "content-location"} else value
            ),
        }
        for name, value in raw_headers.items()
    ]
    observed_names = {name.lower() for name in raw_headers.keys()}
    checks = [
        ("Content-Security-Policy", "Its relevance and correct policy depend on whether the response serves browser content."),
        ("X-Content-Type-Options", "Review MIME handling and the nosniff value in the application context."),
        ("Referrer-Policy", "Review the application's intended referrer disclosure policy."),
        ("Permissions-Policy", "Review which browser features the application needs."),
    ]
    if scheme == "https":
        checks.append(("Strict-Transport-Security", "Review HTTPS coverage before enabling or changing HSTS."))
    observations = [
        {
            "header": name,
            "state": "present" if name.lower() in observed_names else "not_observed",
            "context": context,
        }
        for name, context in checks
    ]
    notes = [
        "Only one HEAD request was sent; response bodies were not analyzed.",
        "Missing headers and their presence alone do not establish a vulnerability or a correct configuration.",
        "The first validated DNS address was pinned for this connection; other addresses were not tested.",
        "Stored URL queries and fragments are redacted; Location and Content-Location also omit embedded credentials.",
        "This is partial redaction: URL paths, custom headers and other response text may still contain sensitive data.",
    ]
    if 300 <= status < 400:
        notes.append("A redirect was returned and was not followed.")
    if status == 405:
        notes.append("HEAD is not allowed here; no GET fallback was attempted.")
    return {
        "module": "web",
        "url": _redact_result_url(normalized_url),
        "resolved_ip": selected_ip,
        "resolved_addresses": addresses,
        "status": status,
        "reason": reason,
        "headers": headers,
        "tls": tls,
        "security_headers": observations,
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "notes": notes,
    }
