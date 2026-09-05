from io import BytesIO

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
    """
    Generate the PDF using the complete scan record.

    All text is wrapped inside its assigned table column.
    No scanner information is changed or removed.
    """

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
        wordWrap="LTR",
        splitLongWords=True,
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=10,
        alignment=TA_LEFT,
        wordWrap="LTR",
        splitLongWords=True,
    )

    header_style = ParagraphStyle(
        "HeaderText",
        parent=normal_style,
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
    )

    story = []

    # ---------------------------------------------------------
    # Get information from scan
    # ---------------------------------------------------------

    url = scan.get("url", "")
    score = scan.get("score")
    grade = scan.get("grade")
    status = scan.get("status", "")

    result = {}

    if scan.get("result_json"):
        import json

        try:
            result = json.loads(scan["result_json"])
        except Exception:
            result = {}

    # ---------------------------------------------------------
    # Title
    # ---------------------------------------------------------

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

    story.append(Spacer(1, 8))

    # ---------------------------------------------------------
    # Checks
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "<b>Security Checks</b>",
            normal_style,
        )
    )

    story.append(Spacer(1, 4))

    # Your scanner uses passed_checks
    checks = result.get("passed_checks", [])

    # Also support checks if present
    if not checks:
        checks = result.get("checks", [])

    table_data = [
        [
            Paragraph("Status", header_style),
            Paragraph("Check", header_style),
            Paragraph("Severity", header_style),
            Paragraph("Evidence", header_style),
        ]
    ]

    for check in checks:
        passed = check.get("passed", False)

        status_text = "PASS" if passed else "FAIL"
        title = check.get("title", "")
        severity = check.get("severity", "")
        evidence = check.get("evidence", "")

        table_data.append(
            [
                Paragraph(
                    status_text,
                    small_style,
                ),
                Paragraph(
                    str(title),
                    small_style,
                ),
                Paragraph(
                    str(severity),
                    small_style,
                ),
                Paragraph(
                    str(evidence),
                    small_style,
                ),
            ]
        )

    # ---------------------------------------------------------
    # IMPORTANT:
    # Total width = 186 mm
    #
    # A4 width = 210 mm
    # Left + right margins = 24 mm
    # Available width = 186 mm
    #
    # Every column has a fixed width.
    # Paragraph automatically wraps text inside it.
    # ---------------------------------------------------------

    check_table = Table(
        table_data,
        colWidths=[
            20 * mm,   # Status
            38 * mm,   # Check
            25 * mm,   # Severity
            103 * mm,  # Evidence
        ],
        repeatRows=1,
        splitByRow=1,
        hAlign="LEFT",
    )

    check_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E5E7EB"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.black,
                ),
                (
                    "FONTNAME",
                    (0,