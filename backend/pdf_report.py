from io import BytesIO
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def make_pdf(scan):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    styles = getSampleStyleSheet()

    # --------------------------------------------------------
    # TITLE STYLE
    # --------------------------------------------------------

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    # --------------------------------------------------------
    # NORMAL TEXT
    # --------------------------------------------------------

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
        wordWrap="LTR",
        splitLongWords=True,
    )

    # --------------------------------------------------------
    # SMALL TABLE TEXT
    # --------------------------------------------------------

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        alignment=TA_LEFT,
        wordWrap="LTR",
        splitLongWords=True,
    )

    # --------------------------------------------------------
    # TABLE HEADER
    # --------------------------------------------------------

    header_style = ParagraphStyle(
        "HeaderText",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        alignment=TA_LEFT,
        wordWrap="LTR",
    )

    story = []

    # ========================================================
    # LOAD SCAN RESULT
    # ========================================================

    url = scan.get("url", "")
    score = scan.get("score")
    grade = scan.get("grade")
    status = scan.get("status", "")

    result = {}

    result_json = scan.get("result_json")

    if result_json:

        try:
            result = json.loads(result_json)

        except Exception:
            result = {}

    # ========================================================
    # REPORT TITLE
    # ========================================================

    story.append(
        Paragraph(
            "Security Health Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Target:</b> {url}",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Score:</b> {score}/100",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Grade:</b> {grade}",
            normal_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Status:</b> {status}",
            normal_style,
        )
    )

    story.append(Spacer(1, 10))

    # ========================================================
    # SECURITY CHECKS
    # ========================================================

    story.append(
        Paragraph(
            "<b>Security Checks</b>",
            normal_style,
        )
    )

    story.append(Spacer(1, 5))

    checks = result.get(
        "passed_checks",
        []
    )

    if not checks:
        checks = result.get(
            "checks",
            []
        )

    # --------------------------------------------------------
    # TABLE HEADER
    # --------------------------------------------------------

    table_data = [
        [
            Paragraph(
                "Status",
                header_style
            ),
            Paragraph(
                "Check",
                header_style
            ),
            Paragraph(
                "Severity",
                header_style
            ),
            Paragraph(
                "Evidence",
                header_style
            ),
        ]
    ]

    # --------------------------------------------------------
    # CHECK ROWS
    # --------------------------------------------------------

    for check in checks:

        passed = check.get(
            "passed",
            False
        )

        status_text = (
            "PASS"
            if passed
            else "FAIL"
        )

        title = check.get(
            "title",
            ""
        )

        severity = check.get(
            "severity",
            ""
        )

        evidence = check.get(
            "evidence",
            ""
        )

        table_data.append(
            [
                Paragraph(
                    str(status_text),
                    small_style
                ),

                Paragraph(
                    str(title),
                    small_style
                ),

                Paragraph(
                    str(severity),
                    small_style
                ),

                Paragraph(
                    str(evidence),
                    small_style
                ),
            ]
        )

    # ========================================================
    # SECURITY CHECK TABLE
    #
    # A4 width:
    # 210 mm
    #
    # Margins:
    # 12 + 12 = 24 mm
    #
    # Available:
    # 186 mm
    #
    # Columns:
    # 20 + 38 + 25 + 103 = 186 mm
    # ========================================================

    check_table = Table(
        table_data,
        colWidths=[
            20 * mm,
            38 * mm,
            25 * mm,
            103 * mm,
        ],
        repeatRows=1,
        splitByRow=True,
        hAlign="LEFT",
    )

    check_table.setStyle(
        TableStyle(
            [

                # Header background
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#E5E7EB"
                    ),
                ),

                # Header text
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.black,
                ),

                # Grid
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),

                # Top alignment
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),

                # Cell padding
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    story.append(check_table)

    story.append(Spacer(1, 12))

    # ========================================================
    # REMEDIATION
    # ========================================================

    story.append(
        Paragraph(
            "<b>Remediation</b>",
            normal_style,
        )
    )

    story.append(Spacer(1, 5))

    remediation = result.get(
        "remediation",
        ""
    )

    if isinstance(
        remediation,
        list
    ):

        for item in remediation:

            story.append(
                Paragraph(
                    str(item),
                    small_style,
                )
            )

            story.append(
                Spacer(1, 4)
            )

    elif remediation:

        story.append(
            Paragraph(
                str(remediation),
                small_style,
            )
        )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Spacer(1, 12)
    )

    story.append(
        Paragraph(
            "Only scan websites you own or are "
            "authorized to assess. "
            "This tool performs passive analysis only.",
            small_style,
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    doc.build(story)

    buffer.seek(0)

    return buffer.getvalue()