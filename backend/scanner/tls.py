import socket
import ssl

from datetime import datetime, timezone


def inspect_tls(hostname):

    result = {

        "title":
            "SSL/TLS inspection",

        "passed":
            False,

        "severity":
            "high",

        "points":
            -20,

        "evidence":
            "",

        "remediation":
            "Use a valid certificate and "
            "modern TLS configuration."
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=8
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as connection:

                certificate = (
                    connection.getpeercert()
                )

                cipher = connection.cipher()

                not_after = (
                    certificate.get(
                        "notAfter"
                    )
                )

                expiry = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(
                    tzinfo=timezone.utc
                )

                now = datetime.now(
                    timezone.utc
                )

                days_remaining = (
                    expiry - now
                ).days

                cipher_bits = (
                    cipher[2]
                    if cipher
                    else 0
                )

                certificate_valid = (
                    days_remaining >= 0
                )

                strong_cipher = (
                    cipher_bits >= 128
                )

                passed = (
                    certificate_valid
                    and strong_cipher
                )

                result["passed"] = passed

                result["points"] = (
                    10
                    if passed
                    else -20
                )

                result["evidence"] = (
                    f"TLS: {connection.version()}, "
                    f"Cipher: {cipher[0] if cipher else 'unknown'}, "
                    f"Bits: {cipher_bits}, "
                    f"Expires: {expiry.date()}, "
                    f"Days remaining: {days_remaining}"
                )

                result["details"] = {

                    "protocol":
                        connection.version(),

                    "cipher":
                        cipher[0]
                        if cipher
                        else None,

                    "bits":
                        cipher_bits,

                    "expires":
                        expiry.isoformat(),

                    "days_remaining":
                        days_remaining
                }

    except Exception as error:

        result["evidence"] = (
            "TLS inspection failed: "
            f"{type(error).__name__}: {error}"
        )

    return result