import requests

from .safe_url import (
    validate_public_url
)

from .headers import (
    analyze_headers
)

from .tls import (
    inspect_tls
)

from .cms import (
    detect_cms
)


USER_AGENT = (
    "VulnScan-Lite/1.0 "
    "(passive security scanner)"
)


def calculate_grade(score):

    if score >= 90:
        return "A"

    if score >= 80:
        return "B+"

    if score >= 70:
        return "B"

    if score >= 60:
        return "C"

    if score >= 50:
        return "D"

    return "F"


def scan(url):

    # Validate target
    url = validate_public_url(url)

    # Passive HTTP request
    response = requests.get(

        url,

        headers={
            "User-Agent": USER_AGENT
        },

        timeout=(
            5,
            10
        ),

        allow_redirects=False,

        stream=True
    )

    # Read maximum 1 MB
    body = next(
        response.iter_content(
            1024 * 1024
        ),
        b""
    )

    html = body.decode(
        response.encoding
        or "utf-8",
        errors="replace"
    )

    headers = dict(
        response.headers
    )

    findings = []

    # Security headers
    findings.extend(
        analyze_headers(headers)
    )

    # HTTPS/TLS
    if url.startswith("https://"):

        hostname = (
            url.split(
                "://",
                1
            )[1]
            .split(
                "/",
                1
            )[0]
        )

        hostname = hostname.split(
            ":",
            1
        )[0]

        findings.append(
            inspect_tls(hostname)
        )

    else:

        findings.append({

            "title":
                "HTTPS",

            "passed":
                False,

            "severity":
                "high",

            "points":
                -20,

            "evidence":
                "Target uses HTTP.",

            "remediation":
                "Enable HTTPS with a valid "
                "certificate and redirect HTTP "
                "traffic to HTTPS."
        })

    # CMS
    findings.append(
        detect_cms(
            html,
            headers
        )
    )

    # Calculate score
    score = 100

    for finding in findings:

        score += int(
            finding.get(
                "points",
                0
            )
        )

    score = max(
        0,
        min(
            100,
            score
        )
    )

    grade = calculate_grade(
        score
    )

    return {

        "url":
            url,

        "http": {

            "status":
                response.status_code,

            "server":
                headers.get(
                    "Server",
                    "Not disclosed"
                ),

            "content_type":
                headers.get(
                    "Content-Type",
                    ""
                )
        },

        "score":
            score,

        "grade":
            grade,

        "passed_checks":
            [
                finding
                for finding in findings
                if finding["passed"]
            ],

        "failed_checks":
            [
                finding
                for finding in findings
                if not finding["passed"]
            ],

        "all_checks":
            findings,

        "notes": [

            "Passive checks only.",

            "No exploit attempts were performed.",

            "Redirects were not followed.",

            "CMS detection is fingerprint-based."
        ]
    }