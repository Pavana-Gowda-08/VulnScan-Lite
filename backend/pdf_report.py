import json
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# ============================================================
# PDF REPORT
# ============================================================

def make_pdf(scan):

    buffer = BytesIO()

    # A4 page
    # 15 mm margins leave enough usable width
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="VulnScan Lite Security Report",
    )

    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "VulnScanTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=22,
        spaceAfter=10,
    )

    heading_style = ParagraphStyle(
        "VulnScanHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=8,
        spaceAfter=6,
    )

    normal_style = ParagraphStyle(
        "VulnScanNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )

    cell_style = ParagraphStyle(
        "VulnScanCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        wordWrap="LTR",
    )

    header_style = ParagraphStyle(
        "VulnScanHeader",
        parent=cell_style,
        fontName="Helvetica-Bold",
    )

    small_style = ParagraphStyle(
        "VulnScanSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Paragraph(
            "VulnScan Lite - Security Scan Report",
            title_style,
        )
    )

    story.append(
        Spacer(
            1,
            4 * mm,
        )
    )

    # ========================================================
    # SCAN INFORMATION
    # ========================================================

    url = scan.get(
        "url",
        "",
    )

    status = scan.get(
        "status",
        "",
    )

    score = scan.get(
        "score",
        "",
    )

    grade = scan.get(
        "grade",
        "",
    )

    info_data = [
        [
            Paragraph(
                "<b>Target URL</b>",
                cell_style,
            ),
            Paragraph(
                str(url),
                cell_style,
            ),
        ],
        [
            Paragraph(
                "<b>Status</b>",
                cell_style,
            ),
            Paragraph(
                str(status),
                cell_style,
            ),
        ],
        [
            Paragraph(
                "<b>Security Score</b>",
                cell_style,
            ),
            Paragraph(
                str(score),
                cell_style,
            ),
        ],
        [
            Paragraph(
                "<b>Grade</b>",
                cell_style,
            ),
            Paragraph(
                str(grade),
                cell_style,
            ),
        ],
    ]

    info_table = Table(
        info_data,
        colWidths=[
            40 * mm,
            135 * mm,
        ],
    )

    info_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.whitesmoke,
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(info_table)

    story.append(
        Spacer(
            1,
            8 * mm,
        )
    )

    # ========================================================
    # RESULT JSON
    # ========================================================

    result_json = scan.get(
        "result_json"
    )

    result = {}

    if isinstance(
        result_json,
        dict,
    ):

        result = result_json

    elif isinstance(
        result_json,
        str,
    ):

        try:

            result = json.loads(
                result_json
            )

        except Exception:

            result = {}

    # ========================================================
    # SECURITY CHECKS
    # ========================================================

    story.append(
        Paragraph(
            "Security Checks",
            heading_style,
        )
    )

    checks = []

    if isinstance(
        result,
        dict,
    ):

        checks = result.get(
            "checks",
            [],
        )

    if not isinstance(
        checks,
        list,
    ):

        checks = []

    # Header row
    table_data = [
        [
            Paragraph(
                "Check",
                header_style,
            ),
            Paragraph(
                "Status",
                header_style,
            ),
            Paragraph(
                "Severity",
                header_style,
            ),
            Paragraph(
                "Evidence / Recommendation",
                header_style,
            ),
        ]
    ]

    for check in checks:

        if not isinstance(
            check,
            dict,
        ):
            continue

        name = check.get(
            "name",
            check.get(
                "check",
                "Unknown",
            ),
        )

        check_status = check.get(
            "status",
            check.get(
                "result",
                "",
            ),
        )

        severity = check.get(
            "severity",
            "",
        )

        # Some scanners use different names
        evidence = check.get(
            "evidence",
            "",
        )

        recommendation = check.get(
            "recommendation",
            "",
        )

        description = check.get(
            "description",
            "",
        )

        # Combine useful information
        evidence_parts = []

        if evidence:
            evidence_parts.append(
                f"<b>Evidence:</b> {evidence}"
            )

        if recommendation:
            evidence_parts.append(
                f"<b>Recommendation:</b> {recommendation}"
            )

        if description:
            evidence_parts.append(
                f"<b>Description:</b> {description}"
            )

        evidence_text = "<br/>".join(
            evidence_parts
        )

        if not evidence_text:
            evidence_text = "No additional information."

        # IMPORTANT:
        # Every cell is a Paragraph.
        # This makes long sentences wrap automatically.
        table_data.append(
            [
                Paragraph(
                    str(name),
                    cell_style,
                ),
                Paragraph(
                    str(check_status),
                    cell_style,
                ),
                Paragraph(
                    str(severity),
                    cell_style,
                ),
                Paragraph(
                    str(evidence_text),
                    cell_style,
                ),
            ]
        )

    if len(table_data) == 1:

        table_data.append(
            [
                Paragraph(
                    "No checks available",
                    cell_style,
                ),
                Paragraph(
                    "",
                    cell_style,
                ),
                Paragraph(
                    "",
                    cell_style,
                ),
                Paragraph(
                    "",
                    cell_style,
                ),
            ]
        )

    # ========================================================
    # SECURITY CHECK TABLE
    # ========================================================

    # Total = 175 mm.
    # This fits inside the A4 page with 15 mm margins.
    results_table = Table(
        table_data,
        colWidths=[
            30 * mm,
            25 * mm,
            25 * mm,
            95 * mm,
        ],
        repeatRows=1,
        splitByRow=True,
    )

    results_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
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
                    5,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(
        results_table
    )

    # ========================================================
    # ERROR
    # ========================================================

    error = scan.get(
        "error"
    )

    if error:

        story.append(
            Spacer(
                1,
                8 * mm,
            )
        )

        story.append(
            Paragraph(
                "Scan Error",
                heading_style,
            )
        )

        story.append(
            Paragraph(
                str(error),
                normal_style,
            )
        )

    # ========================================================
    # FOOTER
    # ========================================================

    story.append(
        Spacer(
            1,
            10 * mm,
        )
    )

    story.append(
        Paragraph(
            "Generated by VulnScan Lite",
            small_style,
        )
    )

    # ========================================================
    # GENERATE
    # ========================================================

    doc.build(
        story
    )

    # Return raw PDF bytes
    buffer.seek(0)

    return buffer.getvalue()