from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
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
    rightMargin=18 * mm,
    leftMargin=18 * mm,
    topMargin=18 * mm,
    bottomMargin=18 * mm
)

styles = getSampleStyleSheet()

styles["Title"].alignment = TA_CENTER

# -----------------------------
# Custom PDF styles
# -----------------------------

table_header_style = ParagraphStyle(
    "TableHeader",
    parent=styles["BodyText"],
    fontSize=8,
    leading=10,
    textColor=colors.white,
    spaceAfter=0,
    spaceBefore=0
)

table_cell_style = ParagraphStyle(
    "TableCell",
    parent=styles["BodyText"],
    fontSize=7.5,
    leading=9,
    spaceAfter=0,
    spaceBefore=0
)

table_status_style = ParagraphStyle(
    "TableStatus",
    parent=table_cell_style,
    alignment=TA_CENTER
)

remediation_style = ParagraphStyle(
    "Remediation",
    parent=styles["BodyText"],
    fontSize=9,
    leading=12,
    spaceAfter=6
)

target_style = ParagraphStyle(
    "Target",
    parent=styles["BodyText"],
    fontSize=9,
    leading=12,
    wordWrap="CJK"
)

story = []

# -----------------------------
# Title
# -----------------------------

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
    Spacer(1, 10)
)

# -----------------------------
# Basic scan information
# -----------------------------

story.append(
    Paragraph(
        f"<b>Target:</b> {result.get('url', '')}",
        target_style
    )
)

story.append(
    Paragraph(
        f"<b>Score:</b> {result.get('score', '-')}/100",
        styles["BodyText"]
    )
)

story.append(
    Paragraph(
        f"<b>Grade:</b> {result.get('grade', '-')}",
        styles["BodyText"]
    )
)

story.append(
    Spacer(1, 15)
)

# -----------------------------
# Findings table
# -----------------------------

rows = [
    [
        Paragraph("Status", table_header_style),
        Paragraph("Check", table_header_style),
        Paragraph("Severity", table_header_style),
        Paragraph("Evidence", table_header_style)
    ]
]

for finding in result.get("all_checks", []):

    status = (
        "PASS"
        if finding.get("passed")
        else "FAIL"
    )

    title = finding.get(
        "title",
        ""
    )

    severity = finding.get(
        "severity",
        ""
    )

    evidence = finding.get(
        "evidence",
        ""
    )

    # Convert everything into Paragraphs.
    # This makes long text wrap automatically.
    rows.append(
        [
            Paragraph(
                status,
                table_status_style
            ),

            Paragraph(
                str(title),
                table_cell_style
            ),

            Paragraph(
                str(severity),
                table_cell_style
            ),

            Paragraph(
                str(evidence),
                table_cell_style
            )
        ]
    )

# A4 width with 18 mm margins
# is approximately 174 mm.
#
# These columns fit within that width.
table = Table(
    rows,
    colWidths=[
        18 * mm,
        42 * mm,
        23 * mm,
        91 * mm
    ],
    repeatRows=1,
    hAlign="LEFT"
)

table.setStyle(
    TableStyle([

        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#1f2937")
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
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),

        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),

        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            5
        ),

        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            5
        ),

        (
            "ALIGN",
            (0, 0),
            (0, -1),
            "CENTER"
        )
    ])
)

story.append(table)

story.append(
    Spacer(1, 15)
)

# -----------------------------
# Remediation section
# -----------------------------

story.append(
    Paragraph(
        "Remediation",
        styles["Heading2"]
    )
)

for finding in result.get(
    "failed_checks",
    []
):

    title = finding.get(
        "title",
        "Security Check"
    )

    remediation = finding.get(
        "remediation",
        "No remediation information available."
    )

    story.append(
        Paragraph(
            f"<b>{title}:</b> {remediation}",
            remediation_style
        )
    )

story.append(
    Spacer(1, 15)
)

# -----------------------------
# Disclaimer
# -----------------------------

story.append(
    Paragraph(
        "Only scan websites you own "
        "or are authorized to assess. "
        "Passive analysis only.",
        styles["Italic"]
    )
)

# -----------------------------
# Build PDF
# -----------------------------

document.build(story)

return buffer.getvalue()