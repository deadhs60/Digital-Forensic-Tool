from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape

def generate_report(data):
    file_path = "forensic_report.pdf"

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph("Digital Forensics Report", styles['Title']))
    elements.append(Spacer(1, 10))

    for section, content in data.items():

        elements.append(Paragraph(f"<b>{escape(section)}</b>", styles['Heading2']))
        elements.append(Spacer(1, 5))

        if isinstance(content, dict):
            for key, value in content.items():
                elements.append(
                    Paragraph(f"<b>{escape(str(key))}:</b> {escape(str(value))}", styles['Normal'])
                )

        elif isinstance(content, list):
            for item in content:
                elements.append(
                    Paragraph(escape(str(item)), styles['Normal'])
                )

        else:
            elements.append(
                Paragraph(escape(str(content)), styles['Normal'])
            )

        elements.append(Spacer(1, 10))

    doc.build(elements)

    return file_path