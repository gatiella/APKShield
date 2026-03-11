"""
apkshield/reports/pdf_report.py
Generates a professional PDF report using ReportLab.
Falls back to a plain-text .txt file if ReportLab is unavailable.
"""
from __future__ import annotations
from apkshield.models import ScanResult, Severity

SEV_HEX = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM":   "#d97706", "LOW":  "#65a30d", "INFO": "#0284c7",
}
RISK_HEX = {
    "CRITICAL RISK": "#dc2626", "HIGH RISK": "#ea580c",
    "MEDIUM RISK":   "#d97706", "LOW RISK":  "#65a30d", "MINIMAL RISK": "#16a34a",
}


def generate(result: ScanResult, output_path: str) -> str:
    try:
        return _generate_pdf(result, output_path)
    except ImportError:
        return _generate_txt(result, output_path.replace(".pdf", "_report.txt"))
    except Exception as e:
        import logging
        logging.getLogger("APKShield").warning(f"PDF generation error: {e}. Falling back to TXT.")
        return _generate_txt(result, output_path.replace(".pdf", "_report.txt"))


def _generate_pdf(result: ScanResult, output_path: str) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER

    W, H = A4
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
        title=f"APKShield Report — {result.apk_name}",
    )
    styles = getSampleStyleSheet()
    story  = []

    def color(hex_str: str):
        h = hex_str.lstrip("#")
        return colors.HexColor("#" + h)

    rc = color(RISK_HEX.get(result.risk_label, "#888888"))

    # ── Styles ────────────────────────────────────────────────────────────────
    h1 = ParagraphStyle("H1", parent=styles["Title"],
                         fontSize=20, textColor=color("#0f4c81"), spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                         fontSize=12, textColor=color("#1e3a5f"), spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("Body", parent=styles["Normal"],
                           fontSize=8.5, spaceAfter=3, leading=12)
    code_s = ParagraphStyle("Code", parent=styles["Code"],
                             fontSize=7, backColor=color("#f1f5f9"),
                             leftIndent=6, rightIndent=6, spaceAfter=3)
    fix_s = ParagraphStyle("Fix", parent=styles["Normal"],
                            fontSize=7.5, textColor=color("#166534"),
                            backColor=color("#dcfce7"), leftIndent=6, spaceAfter=3)

    def hr():
        return HRFlowable(width="100%", thickness=1, color=color("#cbd5e1"), spaceAfter=6)

    counts = result.counts

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("🛡 APKShield Security Report", h1))
    story.append(Paragraph(
        f"<font color='#64748b' size='8'>Generated: {result.scan_time} | "
        f"Duration: {result.duration_secs}s | Tool: APKShield v{result.tool_version}</font>",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.3*cm))
    story.append(hr())

    # Risk score
    story.append(Paragraph(
        f"<b>File:</b> {result.apk_name} &nbsp;|&nbsp; "
        f"<b>Package:</b> {result.package_name or '—'} &nbsp;|&nbsp; "
        f"<b>Version:</b> {result.version_name}",
        body,
    ))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f'Risk Score: <font size="18" color="{RISK_HEX.get(result.risk_label,"#888")}">'
        f'<b>{result.risk_score}/100</b></font> — <b>{result.risk_label}</b>',
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.4*cm))

    # Summary table
    story.append(Paragraph("Findings Summary", h2))
    sum_data  = [["CRITICAL","HIGH","MEDIUM","LOW","INFO","TOTAL"]]
    sum_data += [[str(counts[s]) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO","TOTAL")]]
    t = Table(sum_data, colWidths=[2.7*cm]*6)
    t.setStyle(TableStyle([
        ("ALIGN",      (0,0),(-1,-1),"CENTER"),
        ("FONTSIZE",   (0,0),(-1,-1),8),
        ("FONTNAME",   (0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",   (0,1),(-1,1),14),
        ("FONTNAME",   (0,1),(-1,1),"Helvetica-Bold"),
        ("GRID",       (0,0),(-1,-1),0.4,color("#cbd5e1")),
        ("TEXTCOLOR",  (0,1),(0,1),color("#dc2626")),
        ("TEXTCOLOR",  (1,1),(1,1),color("#ea580c")),
        ("TEXTCOLOR",  (2,1),(2,1),color("#d97706")),
        ("TEXTCOLOR",  (3,1),(3,1),color("#65a30d")),
        ("TEXTCOLOR",  (4,1),(4,1),color("#0284c7")),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, color("#f8fafc")]),
        ("ROWPADDING", (0,0),(-1,-1),4),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # APK info
    story.append(Paragraph("Application Details", h2))
    info = [
        ["Package",    result.package_name or "—"],
        ["Version",    f"{result.version_name} (code {result.version_code})"],
        ["Min SDK",    result.min_sdk or "—"],
        ["Target SDK", result.target_sdk or "—"],
        ["SHA-256",    result.sha256],
        ["MD5",        result.md5],
        ["File Size",  result.file_size_kb],
        ["Debuggable", "YES ⚠️" if result.is_debuggable else "No"],
        ["Backup",     "ENABLED ⚠️" if result.allows_backup else "Disabled"],
    ]
    it = Table(info, colWidths=[3.5*cm,13.5*cm])
    it.setStyle(TableStyle([
        ("FONTSIZE",     (0,0),(-1,-1),7.5),
        ("FONTNAME",     (0,0),(0,-1),"Helvetica-Bold"),
        ("BACKGROUND",   (0,0),(0,-1),color("#e8f0fe")),
        ("GRID",         (0,0),(-1,-1),0.3,color("#e2e8f0")),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white,color("#f8fafc")]),
        ("ROWPADDING",   (0,0),(-1,-1),3),
        ("WORDWRAP",     (1,0),(1,-1),"CJK"),
        ("VALIGN",       (0,0),(-1,-1),"TOP"),
    ]))
    story.append(it)

    # ── Findings ──────────────────────────────────────────────────────────────
    if result.findings:
        story.append(PageBreak())
        story.append(Paragraph(f"Detailed Findings ({counts['TOTAL']} total)", h2))
        for i, f in enumerate(result.findings, 1):
            sc = color(SEV_HEX.get(f.severity.value,"#888888"))
            rows = [
                [f"#{i}", f.severity.value, f.title,
                 f.owasp or "—", f.cwe or "—", f"CVSS {f.cvss:.1f}" if f.cvss else "—"],
            ]
            ht = Table(rows, colWidths=[.8*cm,1.9*cm,9.8*cm,1.3*cm,1.8*cm,1.4*cm])
            ht.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1),color("#1e3a5f")),
                ("TEXTCOLOR", (0,0),(-1,-1),colors.white),
                ("TEXTCOLOR", (1,0),(1,0), sc),
                ("FONTSIZE",  (0,0),(-1,-1),7.5),
                ("FONTNAME",  (0,0),(-1,-1),"Helvetica-Bold"),
                ("ROWPADDING",(0,0),(-1,-1),3),
            ]))
            detail = [["Category",   f.category]]
            if f.description:  detail.append(["Description", f.description])
            if f.evidence:     detail.append(["Evidence",    f.evidence[:200]])
            if f.file_path:    detail.append(["Location",    f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path])
            if f.confidence:   detail.append(["Confidence",  f.confidence])
            if f.remediation:  detail.append(["Remediation", f.remediation])
            dt = Table(detail, colWidths=[2.2*cm,14.8*cm])
            dt.setStyle(TableStyle([
                ("FONTSIZE",     (0,0),(-1,-1),7),
                ("FONTNAME",     (0,0),(0,-1),"Helvetica-Bold"),
                ("BACKGROUND",   (0,0),(0,-1),color("#f8fafc")),
                ("GRID",         (0,0),(-1,-1),0.2,color("#e2e8f0")),
                ("WORDWRAP",     (1,0),(1,-1),"CJK"),
                ("VALIGN",       (0,0),(-1,-1),"TOP"),
                ("ROWPADDING",   (0,0),(-1,-1),2.5),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white,color("#fafafa")]),
            ]))
            story.append(KeepTogether([ht, dt, Spacer(1, 0.25*cm)]))

    # ── OWASP table ───────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("OWASP Mobile Top 10 Coverage", h2))
    from apkshield.rules.owasp import OWASP_MOBILE_TOP10
    owasp   = result.owasp_coverage
    o_data  = [["ID","Category","Findings","Max Severity"]]
    for oid, info in owasp.items():
        o_data.append([oid, OWASP_MOBILE_TOP10[oid],
                        str(info["count"]), info["max_severity"] or "✓ Pass"])
    ot = Table(o_data, colWidths=[1.3*cm,9*cm,2*cm,3*cm])
    ot.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,0),color("#1e3a5f")),
        ("TEXTCOLOR",    (0,0),(-1,0),colors.white),
        ("FONTNAME",     (0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1),7.5),
        ("GRID",         (0,0),(-1,-1),0.3,color("#cbd5e1")),
        ("ROWBACKGROUNDS",(1,0),(-1,-1),[colors.white,color("#f8fafc")]),
        ("ROWPADDING",   (0,0),(-1,-1),3.5),
    ]))
    story.append(ot)
    story.append(Spacer(1,.3*cm))
    story.append(hr())
    story.append(Paragraph(
        f"<font color='#94a3b8' size='7'>APKShield v{result.tool_version} — "
        "For authorised security assessment only.</font>",
        styles["Normal"],
    ))

    doc.build(story)
    return output_path


def _generate_txt(result: ScanResult, output_path: str) -> str:
    counts = result.counts
    lines  = [
        "=" * 70,
        f"APKShield v{result.tool_version} — Security Report",
        "=" * 70,
        f"File     : {result.apk_name}",
        f"Package  : {result.package_name}",
        f"Version  : {result.version_name} (code {result.version_code})",
        f"SHA-256  : {result.sha256}",
        f"Scan     : {result.scan_time}",
        f"Duration : {result.duration_secs}s",
        "",
        f"Risk Score : {result.risk_score}/100  ({result.risk_label})",
        "",
        "SUMMARY",
        "-" * 40,
        *(f"  {s}: {counts[s]}" for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO","TOTAL")),
        "",
        "FINDINGS",
        "-" * 40,
    ]
    for i, f in enumerate(result.findings, 1):
        lines += [
            f"\n[{i:03d}] [{f.severity.value}] {f.title}",
            f"       Category   : {f.category}",
            f"       OWASP      : {f.owasp}  |  CWE: {f.cwe}  |  Confidence: {f.confidence}",
        ]
        if f.description: lines.append(f"       Description: {f.description}")
        if f.evidence:    lines.append(f"       Evidence   : {f.evidence[:150]}")
        if f.file_path:   lines.append(f"       Location   : {f.file_path}:{f.line_number}")
        if f.remediation: lines.append(f"       Fix        : {f.remediation}")
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return output_path
