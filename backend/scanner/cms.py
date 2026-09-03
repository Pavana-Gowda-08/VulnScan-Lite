import re

from bs4 import BeautifulSoup


CMS_BASELINES = {

    "wordpress":
        "7.1"
}


def version_tuple(version):

    numbers = re.findall(
        r"\d+",
        version or ""
    )

    return tuple(
        int(number)
        for number in numbers[:3]
    )


def detect_cms(html, headers):

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    generator = soup.find(
        "meta",
        attrs={
            "name": re.compile(
                "^generator$",
                re.I
            )
        }
    )

    generator_text = ""

    if generator:

        generator_text = generator.get(
            "content",
            ""
        )

    powered_by = headers.get(
        "X-Powered-By",
        ""
    )

    combined = (
        generator_text
        + " "
        + powered_by
    )

    cms = None
    version = None

    if (
        re.search(
            r"WordPress",
            combined,
            re.I
        )
        or re.search(
            r"/wp-(content|includes)/",
            html,
            re.I
        )
    ):

        cms = "WordPress"

    elif (
        re.search(
            r"Drupal",
            combined,
            re.I
        )
        or re.search(
            r"drupalSettings",
            html,
            re.I
        )
    ):

        cms = "Drupal"

    version_match = re.search(

        r"(WordPress|Drupal)"
        r"[ /:-]*"
        r"([0-9]+(?:\.[0-9]+){0,2})",

        combined,

        re.I
    )

    if version_match:

        version = version_match.group(2)

    if not cms:

        return {

            "title":
                "CMS detection",

            "passed":
                True,

            "severity":
                "info",

            "points":
                0,

            "evidence":
                "No supported CMS fingerprint detected.",

            "remediation":
                "No action required. "
                "Passive detection may miss customized sites."
        }

    if (
        cms.lower() == "wordpress"
        and version
    ):

        baseline = CMS_BASELINES[
            "wordpress"
        ]

        outdated = (
            version_tuple(version)
            <
            version_tuple(baseline)
        )

        return {

            "title":
                "WordPress version detection",

            "passed":
                not outdated,

            "severity":
                "high"
                if outdated
                else "info",

            "points":
                10
                if not outdated
                else -20,

            "evidence":
                (
                    f"Detected WordPress {version}. "
                    f"Configured maintained baseline: "
                    f"{baseline}."
                ),

            "remediation":
                (
                    "Update WordPress and installed "
                    "plugins/themes to supported "
                    "security releases."
                )
        }

    return {

        "title":
            f"{cms} detection",

        "passed":
            True,

        "severity":
            "info",

        "points":
            0,

        "evidence":
            (
                f"Detected {cms}"
                + (
                    f" version {version}"
                    if version
                    else ""
                )
            ),

        "remediation":
            (
                "Keep the CMS and its extensions "
                "on supported security releases."
            )
    }