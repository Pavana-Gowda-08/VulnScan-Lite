from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
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

    styles["Title"].alignment = TA_CENTER

    # ---------------------------------------------------------
    # TABLE TEXT STYLE
    # This is the important fix.
    # Paragraph automatically wraps text inside the cell.
    # ---------------------------------------------------------

    table_style = ParagraphStyle(
        "TableText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="LTR",
        splitLongWords=True,
        spaceAfter=0,
        spaceBefore=0
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="LTR",
        splitLongWords=True,
        spaceAfter=0,
        spaceBefore=0
    )

    story = []

    # ---------------------------------------------------------
    # TITLE
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # TARGET
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            f"<b>Target:</b> "
            f"{result['url']}",
            styles["BodyText"]
        )
    )

    # ---------------------------------------------------------
    # SCORE
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            f"<b>Score:</b> "
            f"{result['score']}/100",
            styles["BodyText"]
        )
    )

    # ---------------------------------------------------------
    # GRADE
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # TABLE HEADER
    # ---------------------------------------------------------

    rows = [
        [
            Paragraph(
                "Status",
                table_header_style
            ),

            Paragraph(
                "Check",
                table_header_style
            ),

            Paragraph(
                "Severity",
                table_header_style
            ),

            Paragraph(
                "Evidence",
                table_header_style
            )
        ]
    ]

    # ---------------------------------------------------------
    # CHECK ROWS
    # ---------------------------------------------------------

    for finding in result["all_checks"]:

        status = (
            "PASS"
            if finding["passed"]
            else "FAIL"
        )

        title = finding["title"]

        severity = finding.get(
            "severity",
            ""
        )

        evidence = finding.get(
            "evidence",
            ""
        )[:180]

        rows.append(
            [
                Paragraph(
                    status,
                    table_style
                ),

                Paragraph(
                    str(title),
                    table_style
                ),

                Paragraph(
                    str(severity),
                    table_style
                ),

                Paragraph(
                    str(evidence),
                    table_style
                )
            ]
        )

    # ---------------------------------------------------------
    # TABLE
    #
    # Original column widths are preserved.
    #
    # Paragraph objects make the text wrap inside each
    # respective column.
    # ---------------------------------------------------------

    table = Table(
        rows,
        colWidths=[
            50,
            130,
            65,
            280
        ],
        repeatRows=1,
        splitByRow=True
    )

    table.setStyle(
        TableStyle(
            [

                # Header background
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.white(
                        "#1f2937"
                    )
                ),

                # Header text
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                # Grid
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey
                ),

                # Top alignment
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                # Font size
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),

                # Cell padding
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4
                )
            ]
        )
    )

    story.append(table)

    story.append(
        Spacer(
            1,
            15
        )
    )

    # ---------------------------------------------------------
    # REMEDIATION
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Remediation",
            styles["Heading2"]
        )
    )

    for finding in result["failed_checks"]:

        remediation_text = (
            f"<b>{finding['title']}"
            f":</b> "
            f"{finding['remediation']}"
        )

        story.append(
            Paragraph(
                remediation_text,
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

    # ---------------------------------------------------------
    # DISCLAIMER
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Only scan websites you own "
            "or are authorized to assess. "
            "Passive analysis only.",
            styles["Italic"]
        )
    )

    # ---------------------------------------------------------
    # BUILD PDF
    # ---------------------------------------------------------

    document.build(
        story
    )

    return buffer.getvalue()