import ipaddress
import socket

from urllib.parse import urlparse


class UnsafeTarget(ValueError):
    pass


def is_public_ip(ip_text):

    ip = ipaddress.ip_address(ip_text)

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_public_url(url):

    url = url.strip()

    parsed = urlparse(url)

    if parsed.scheme not in (
        "http",
        "https"
    ):
        raise UnsafeTarget(
            "Only HTTP and HTTPS URLs are allowed."
        )

    if not parsed.hostname:
        raise UnsafeTarget(
            "Hostname is required."
        )

    if parsed.username or parsed.password:
        raise UnsafeTarget(
            "URLs containing credentials are not allowed."
        )

    if parsed.port not in (
        None,
        80,
        443
    ):
        raise UnsafeTarget(
            "Custom ports are disabled."
        )

    hostname = parsed.hostname

    try:

        results = socket.getaddrinfo(
            hostname,
            parsed.port or (
                443
                if parsed.scheme == "https"
                else 80
            ),
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:

        raise UnsafeTarget(
            "Hostname could not be resolved."
        )

    addresses = {
        result[4][0]
        for result in results
    }

    if not addresses:

        raise UnsafeTarget(
            "No IP address found."
        )

    for ip in addresses:

        if not is_public_ip(ip):

            raise UnsafeTarget(
                "Private or internal targets are blocked."
            )

    normalized = (
        f"{parsed.scheme}://"
        f"{hostname}"
    )

    if parsed.port:

        normalized += f":{parsed.port}"

    normalized += (
        parsed.path
        if parsed.path
        else "/"
    )

    if parsed.query:

        normalized += "?" + parsed.query

    return normalized