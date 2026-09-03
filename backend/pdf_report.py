from io import BytesIO

from reportlab.lib import colors

from reportlab.lib.pagesizes import A4

from reportlab.lib.styles import (
    getSampleStyleSheet
)

from reportlab.lib.enums import TA_CENTER

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def make_pdf(result):

    buffer = BytesIO()

    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=36,

        leftMargin=36,

        topMargin=36,

        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    styles["Title"].alignment = (
        TA_CENTER
    )

    story = []

    story.append(

        Paragraph(
            "VulnScan Lite",
            styles["Title"]
        )
    )

    story.append(

        Paragraph(
            "Security Health Report",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    story.append(

        Paragraph(
            f"<b>Target:</b> "
            f"{result['url']}",
            styles["BodyText"]
        )
    )

    story.append(

        Paragraph(
            f"<b>Score:</b> "
            f"{result['score']}/100",
            styles["BodyText"]
        )
    )

    story.append(

        Paragraph(
            f"<b>Grade:</b> "
            f"{result['grade']}",
            styles["BodyText"]
        )
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    rows = [

        [
            "Status",
            "Check",
            "Severity",
            "Evidence"
        ]
    ]

    for finding in result[
        "all_checks"
    ]:

        rows.append([

            (
                "PASS"
                if finding["passed"]
                else "FAIL"
            ),

            finding["title"],

            finding.get(
                "severity",
                ""
            ),

            finding.get(
                "evidence",
                ""
            )[:180]
        ])

    table = Table(

        rows,

        colWidths=[
            50,
            130,
            65,
            280
        ],

        repeatRows=1
    )

    table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#1f2937"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(table)

    story.append(
        Spacer(
            1,
            15
        )
    )

    story.append(

        Paragraph(
            "Remediation",
            styles["Heading2"]
        )
    )

    for finding in result[
        "failed_checks"
    ]:

        story.append(

            Paragraph(

                (
                    f"<b>{finding['title']}"
                    f":</b> "
                    f"{finding['remediation']}"
                ),

                styles["BodyText"]
            )
        )

        story.append(
            Spacer(
                1,
                7
            )
        )

    story.append(
        Spacer(
            1,
            15
        )
    )

    story.append(

        Paragraph(
            "Only scan websites you own "
            "or are authorized to assess. "
            "Passive analysis only.",
            styles["Italic"]
        )
    )

    document.build(
        story
    )

    return buffer.getvalue()