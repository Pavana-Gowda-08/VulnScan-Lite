from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
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
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleCustom",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=22,
        spaceAfter=10,
    )

    heading_style = ParagraphStyle(
        "HeadingCustom",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=8,
        spaceAfter=6,
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
    )

    small_style = ParagraphStyle(
        "SmallCustom",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )

    cell_style = ParagraphStyle(
        "CellCustom",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )

    header_style = ParagraphStyle(
        "HeaderCustom",
        parent=cell_style,
        fontName="Helvetica-Bold",
    )

    story = []

    # --------------------------------------------------
    # TITLE
    # --------------------------------------------------

    story.append(
        Paragraph(
            "VulnScan Lite - Security Scan Report",
            title_style,
        )
    )

    story.append(Spacer(1, 5 * mm))

    # --------------------------------------------------
    # BASIC SCAN INFORMATION
    # --------------------------------------------------

    url = scan.get("url", "")
    status = scan.get("status", "")
    score = scan.get("score", "")
    grade = scan.get("grade", "")

    info_data = [
        [
            Paragraph("<b>Target URL</b>", cell_style),
            Paragraph(str(url), cell_style),
        ],
        [
            Paragraph("<b>Status</b>", cell_style),
            Paragraph(str(status), cell_style),
        ],
        [
            Paragraph("<b>Security Score</b>", cell_style),
            Paragraph(str(score), cell_style),
        ],
        [
            Paragraph("<b>Grade</b>", cell_style),
            Paragraph(str(grade), cell_style),
        ],
    ]

    info_table = Table(
        info_data,
        colWidths=[40 * mm, 135 * mm],
        repeatRows=0,
    )

    info_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(info_table)
    story.append(Spacer(1, 8 * mm))

    # --------------------------------------------------
    # CHECK RESULTS
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Security Checks",
            heading_style,
        )
    )

    result_json = scan.get("result_json")

    checks = []

    if isinstance(result_json, dict):
        checks = result_json.get("checks", [])

    elif isinstance(result_json, list):
        checks = result_json

    # If result_json is stored as JSON text
    if isinstance(result_json, str):
        try:
            import json

            parsed = json.loads(result_json)

            if isinstance(parsed, dict):
                checks = parsed.get("checks", [])

            elif isinstance(parsed, list):
                checks = parsed

        except Exception:
            checks = []

    table_data = [
        [
            Paragraph("Check", header_style),
            Paragraph("Status", header_style),
            Paragraph("Severity", header_style),
            Paragraph("Evidence / Recommendation", header_style),
        ]
    ]

    for check in checks:

        if not isinstance(check, dict):
            continue

        name = check.get(
            "name",
            check.get("check", "Unknown")
        )

        check_status = check.get(
            "status",
            check.get("result", "")
        )

        severity = check.get(
            "severity",
            ""
        )

        evidence = check.get(
            "evidence",
            check.get(
                "recommendation",
                check.get(
                    "description",
                    ""
                )
            )
        )

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
                    str(evidence),
                    cell_style,
                ),
            ]
        )

    if len(table_data) == 1:
        table_data.append(
            [
                Paragraph("No checks available", cell_style),
                Paragraph("", cell_style),
                Paragraph("", cell_style),
                Paragraph("", cell_style),
            ]
        )

    results_table = Table(
        table_data,
        colWidths=[
            30 * mm,
            25 * mm,
            25 * mm,
            95 * mm,
        ],
        repeatRows=1,
    )

    results_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(results_table)

    # --------------------------------------------------
    # ERROR INFORMATION
    # --------------------------------------------------

    error = scan.get("error")

    if error:
        story.append(Spacer(1, 8 * mm))

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

    # --------------------------------------------------
    # FOOTER
    # --------------------------------------------------

    story.append(Spacer(1, 10 * mm))

    story.append(
        Paragraph(
            "Generated by VulnScan Lite",
            small_style,
        )
    )

    # --------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------

    doc.build(story)

    buffer.seek(0)

    return buffer