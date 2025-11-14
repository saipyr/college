from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
import io

def generate_pdf(findings):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20*mm, height - 20*mm, "SEHCS Compliance Report")
    c.setFont("Helvetica", 10)
    y = height - 30*mm
    total = len(findings)
    passed = sum(1 for f in findings if f["compliant"])
    score = (passed / total * 100) if total else 0
    c.drawString(20*mm, y, f"Total Findings: {total}  Passed: {passed}  Score: {score:.1f}%")
    y -= 10*mm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20*mm, y, "Details")
    y -= 8*mm
    c.setFont("Helvetica", 9)
    for f in findings[:200]:
        line = f"{f['device_id']} | {f['rule_id']} | {f['category']} | {'PASS' if f['compliant'] else 'FAIL'} | {f.get('severity','')}"
        c.drawString(20*mm, y, line[:100])
        y -= 6*mm
        if y < 20*mm:
            c.showPage()
            y = height - 20*mm
            c.setFont("Helvetica", 9)
    c.save()
    buf.seek(0)
    return buf.getvalue()