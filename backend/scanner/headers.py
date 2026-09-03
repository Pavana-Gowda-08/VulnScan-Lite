SECURITY_HEADERS = [

    (
        "Content-Security-Policy",
        "CSP helps reduce the impact of content-injection attacks."
    ),

    (
        "X-Frame-Options",
        "X-Frame-Options helps protect against clickjacking."
    ),

    (
        "Strict-Transport-Security",
        "HSTS tells browsers to prefer HTTPS."
    )
]


def analyze_headers(headers):

    findings = []

    for name, description in SECURITY_HEADERS:

        value = headers.get(name)

        present = bool(value)

        if name == "Content-Security-Policy":

            remediation = (
                "Add a suitable Content-Security-Policy "
                "header for your application."
            )

        elif name == "X-Frame-Options":

            remediation = (
                "Add X-Frame-Options: SAMEORIGIN "
                "or DENY if framing is not required."
            )

        else:

            remediation = (
                "After HTTPS is correctly configured, add "
                "Strict-Transport-Security: "
                "max-age=31536000; includeSubDomains"
            )

        findings.append({

            "id": name.lower().replace(
                "-",
                "_"
            ),

            "title": name,

            "passed": present,

            "severity": "medium",

            "points": 10 if present else -10,

            "evidence": (
                value
                if value
                else "Header not present"
            ),

            "description": description,

            "remediation": remediation
        })

    return findings