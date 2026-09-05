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


def make_pdf(scan):

    buffer = BytesIO()

    # =========================================================
    # PAGE
    # =========================================================

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=15 * mm,
        title="VulnScan Lite Security Health Report",
    )

    # =========================================================
    # STYLES
    # =========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=17,
        leading=21,
        spaceAfter=8,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=8,
        spaceAfter=6,
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )

    cell_style = ParagraphStyle(
        "ReportCell",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=9.5,
        wordWrap="LTR",
        splitLongWords=True,
    )

    header_style = ParagraphStyle(
        "ReportHeader",
        parent=cell_style,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10,
    )

    remediation_style = ParagraphStyle(
        "Remediation",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        wordWrap="LTR",
        splitLongWords=True,
    )

    story = []

    # =========================================================
    # TITLE
    # =========================================================

    story.append(
        Paragraph(
            "VulnScan Lite - Security Health Report",
            title_style,
        )
    )

    # =========================================================
    # BASIC INFORMATION
    # =========================================================

    target = str(
        scan.get("url", "")
    )

    score = str(
        scan.get("score", "")
    )

    grade = str(
        scan.get("grade", "")
    )

    status = str(
        scan.get("status", "")
    )

    info_data = [
        [
            Paragraph("<b>Target</b>", cell_style),
            Paragraph(target, cell_style),
        ],
        [
            Paragraph("<b>Score</b>", cell_style),
            Paragraph(
                f"{score}/100",
                cell_style,
            ),
        ],
        [
            Paragraph("<b>Grade</b>", cell_style),
            Paragraph(grade, cell_style),
        ],
        [
            Paragraph("<b>Status</b>", cell_style),
            Paragraph(status, cell_style),
        ],
    ]

    info_table = Table(
        info_data,
        colWidths=[
            32 * mm,
            148 * mm,
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
            7 * mm,
        )
    )

    # =========================================================
    # LOAD RESULT JSON
    # =========================================================

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

    # =========================================================
    # SECURITY CHECKS
    # =========================================================

    story.append(
        Paragraph(
            "Security Checks",
            heading_style,
        )
    )

    checks = result.get(
        "checks",
        [],
    )

    if not isinstance(
        checks,
        list,
    ):
        checks = []

    # ---------------------------------------------------------
    # TABLE HEADER
    # ---------------------------------------------------------

    table_data = [
        [
            Paragraph(
                "Status",
                header_style,
            ),
            Paragraph(
                "Check",
                header_style,
            ),
            Paragraph(
                "Severity",
                header_style,
            ),
            Paragraph(
                "Evidence",
                header_style,
            ),
        ]
    ]

    # ---------------------------------------------------------
    # CHECK ROWS
    # ---------------------------------------------------------

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

        evidence = check.get(
            "evidence",
            check.get(
                "description",
                "",
            ),
        )

        # -----------------------------------------------------
        # Convert everything to safe strings
        # -----------------------------------------------------

        status_text = str(
            check_status
        )

        name_text = str(
            name
        )

        severity_text = str(
            severity
        )

        evidence_text = str(
            evidence
        )

        # -----------------------------------------------------
        # IMPORTANT:
        # Every cell is a Paragraph.
        # Long URLs, headers and sentences wrap.
        # -----------------------------------------------------

        table_data.append(
            [
                Paragraph(
                    status_text,
                    cell_style,
                ),
                Paragraph(
                    name_text,
                    cell_style,
                ),
                Paragraph(
                    severity_text,
                    cell_style,
                ),
                Paragraph(
                    evidence_text,
                    cell_style,
                ),
            ]
        )

    if len(table_data) == 1:

        table_data.append(
            [
                Paragraph(
                    "N/A",
                    cell_style,
                ),
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
            ]
        )

    # =========================================================
    # SECURITY CHECK TABLE
    # =========================================================

    # A4 width = 210 mm
    #
    # Margins:
    # 12 mm + 12 mm
    #
    # Available:
    # 186 mm
    #
    # Columns:
    # 20 + 38 + 25 + 103 = 186 mm
    #
    # Therefore NOTHING goes outside the page.

    results_table = Table(
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

    # =========================================================
    # REMEDIATION
    # =========================================================

    remediation = result.get(
        "remediation",
        "",
    )

    # Some versions of the scanner may use recommendations
    if not remediation:

        remediation = result.get(
            "recommendation",
            "",
        )

    # If remediation is a list
    if isinstance(
        remediation,
        list,
    ):

        remediation_text = "<br/><br/>".join(
            str(item)
            for item in remediation
        )

    else:

        remediation_text = str(
            remediation
        )

    if remediation_text:

        story.append(
            Spacer(
                1,
                7 * mm,
            )
        )

        story.append(
            Paragraph(
                "Remediation",
                heading_style,
            )
        )

        # This is also a Paragraph,
        # so long remediation text wraps.
        story.append(
            Paragraph(
                remediation_text,
                remediation_style,
            )
        )

    # =========================================================
    # DISCLAIMER
    # =========================================================

    story.append(
        Spacer(
            1,
            7 * mm,
        )
    )

    disclaimer = (
        "Only scan websites you own or are authorized "
        "to assess. Passive analysis only."
    )

    story.append(
        Paragraph(
            disclaimer,
            small_style,
        )
    )

    # =========================================================
    # FOOTER
    # =========================================================

    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )

    story.append(
        Paragraph(
            "Generated by VulnScan Lite",
            small_style,
        )
    )

    # =========================================================
    # BUILD PDF
    # =========================================================

    doc.build(
        story
    )

    buffer.seek(0)

    return buffer.getvalue()