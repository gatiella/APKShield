"""
apkshield/reports/html_report.py
Generates a dark-themed, single-file HTML report.
"""
from __future__ import annotations
from typing import Dict, List
from apkshield.models import ScanResult, Finding
from apkshield.rules.owasp import OWASP_MOBILE_TOP10, OWASP_DESCRIPTIONS

SEV_COLOR = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#d97706","LOW":"#65a30d","INFO":"#0284c7"}
SEV_BG    = {"CRITICAL":"rgba(220,38,38,.10)","HIGH":"rgba(234,88,12,.10)",
             "MEDIUM":"rgba(217,119,6,.10)","LOW":"rgba(101,163,13,.10)","INFO":"rgba(2,132,199,.10)"}
RISK_COLOR = {"CRITICAL RISK":"#dc2626","HIGH RISK":"#ea580c",
              "MEDIUM RISK":"#d97706","LOW RISK":"#65a30d","MINIMAL RISK":"#16a34a"}
CONF_COLOR = {"HIGH":"#4ade80","MEDIUM":"#facc15","LOW":"#f87171"}


def generate(result: ScanResult, output_path: str) -> str:
    html = _build(result)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def _e(s) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def _build(r: ScanResult) -> str:
    counts    = r.counts
    owasp     = r.owasp_coverage
    rc        = RISK_COLOR.get(r.risk_label, "#888")
    by_cat    = _group_by_category(r.findings)

    # ── Severity bars ──────────────────────────────────────────────────────
    sev_cards = "".join(
        f'<div class="sev-card"><div class="sev-num" style="color:{SEV_COLOR[s]}">'
        f'{counts[s]}</div><div class="sev-lbl">{s}</div></div>'
        for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
    )

    # ── Executive summary ──────────────────────────────────────────────────
    critical_titles = [f.title for f in r.findings if f.severity.value == "CRITICAL"][:5]
    exec_items = "".join(f"<li>{_e(t)}</li>" for t in critical_titles)
    exec_block = f"""
    <div class="card exec-summary">
      <h2>⚡ Executive Summary</h2>
      <p>
        <b>{_e(r.apk_name)}</b> received a risk score of
        <span style="color:{rc};font-weight:700">{r.risk_score}/100 ({_e(r.risk_label)})</span>
        with <b>{counts["CRITICAL"]} critical</b> and <b>{counts["HIGH"]} high</b> severity findings
        across {len(by_cat)} categories.
        {f"<br><b>Top critical issues:</b><ul>{exec_items}</ul>" if exec_items else ""}
      </p>
      {"<p style='color:#fbbf24'>⚠️ Application is <b>debuggable</b> — never ship this build.</p>" if r.is_debuggable else ""}
      {"<p style='color:#fbbf24'>⚠️ ADB <b>backup</b> is enabled — app data can be extracted via USB.</p>" if r.allows_backup else ""}
      {"<p style='color:#4ade80'>✅ Code obfuscation detected.</p>" if r.is_obfuscated else
       "<p style='color:#f87171'>❌ Code appears <b>unobfuscated</b> — reverse engineering is trivial.</p>" if r.is_obfuscated is False else ""}
    </div>"""

    # ── Metadata cards ─────────────────────────────────────────────────────
    meta_left = _meta_card("📱 App Info", [
        ("Package",    r.package_name or "unknown"),
        ("Version",    f"{r.version_name} (code {r.version_code})"),
        ("Min SDK",    r.min_sdk  or "unknown"),
        ("Target SDK", r.target_sdk or "unknown"),
        ("File Size",  r.file_size_kb),
        ("Scan Time",  r.scan_time),
        ("Duration",   f"{r.duration_secs}s"),
    ])
    meta_right = f"""<div class="card">
      <h2>🔍 File Integrity</h2>
      <div class="meta-row"><span class="mk">SHA-256</span></div>
      <div class="hash">{_e(r.sha256)}</div>
      <div class="meta-row" style="margin-top:.5rem"><span class="mk">SHA-1</span></div>
      <div class="hash">{_e(r.sha1)}</div>
      <div class="meta-row" style="margin-top:.5rem"><span class="mk">MD5</span></div>
      <div class="hash">{_e(r.md5)}</div>
      <div class="meta-row" style="margin-top:.6rem">
        <span class="mk">Native Libraries</span>
        <span class="mv">{len(r.native_libs)}</span>
      </div>
      <div class="meta-row">
        <span class="mk">Third-party SDKs</span>
        <span class="mv">{len(r.third_party_sdks)}</span>
      </div>
    </div>"""

    # ── Findings HTML ──────────────────────────────────────────────────────
    findings_html = ""
    if r.findings:
        for cat, items in by_cat.items():
            rows = "".join(_finding_card(f) for f in items)
            findings_html += f"""
            <div class="cat-section">
              <h3 class="cat-title">{_e(cat)} <span class="cat-badge">{len(items)}</span></h3>
              <div class="findings-list">{rows}</div>
            </div>"""
    else:
        findings_html = '<p style="color:#4ade80;padding:1rem">✅ No security findings.</p>'

    # ── OWASP table ────────────────────────────────────────────────────────
    owasp_rows = ""
    for oid, info in owasp.items():
        n    = info["count"]
        ms   = info["max_severity"]
        col  = SEV_COLOR.get(ms,"#888") if n else "#16a34a"
        stat = (f'<span style="color:{col};font-weight:600">{_e(ms)} ({n})</span>'
                if n else '<span style="color:#16a34a">✓ Pass</span>')
        desc = OWASP_DESCRIPTIONS.get(oid, "")
        owasp_rows += f"<tr><td><b>{oid}</b></td><td>{OWASP_MOBILE_TOP10[oid]}</td><td style='font-size:.78rem;color:var(--muted)'>{_e(desc)}</td><td>{stat}</td></tr>"

    # ── Permissions ────────────────────────────────────────────────────────
    from apkshield.rules.permissions import DANGEROUS_PERMISSIONS
    perm_items = ""
    for p in sorted(r.permissions):
        if p in DANGEROUS_PERMISSIONS:
            sev, desc, _fix = DANGEROUS_PERMISSIONS[p]
            col = SEV_COLOR.get(sev.value,"#888")
            perm_items += (f'<li class="perm-item" style="border-left:3px solid {col};background:rgba(0,0,0,.2)">'
                           f'<span class="pn">{_e(p)}</span>'
                           f'<span class="pd" style="color:{col}">[{sev.value}]</span>'
                           f'<span class="pd">{_e(desc)}</span></li>')
        else:
            perm_items += (f'<li class="perm-item normal"><span class="pn">{_e(p)}</span></li>')

    # ── SDK list ───────────────────────────────────────────────────────────
    sdk_items = "".join(
        f'<li class="perm-item normal"><span class="pn">{_e(s)}</span></li>'
        for s in r.third_party_sdks
    ) or "<li class='perm-item normal' style='color:var(--muted)'>None detected</li>"

    # ── Certificates ───────────────────────────────────────────────────────
    cert_cards = ""
    for c in r.certificates:
        cert_cards += f"""<div class="cert-card">
          <div class="cert-field"><b>Subject CN:</b> {_e(c.subject_cn)}</div>
          <div class="cert-field"><b>Issuer CN:</b>  {_e(c.issuer_cn)}</div>
          <div class="cert-field"><b>Algorithm:</b>  {_e(c.algorithm)}</div>
          <div class="cert-field"><b>Key Size:</b>   {c.key_bits} bits</div>
          <div class="cert-field"><b>Expires:</b>    {_e(c.not_after)}</div>
          {"<div class='cert-field' style='color:#f87171'>⚠️ Self-signed</div>" if c.is_self_signed else ""}
          {"<div class='cert-field' style='color:#dc2626'>❌ EXPIRED</div>" if c.is_expired else ""}
        </div>"""
    cert_section = cert_cards or "<p style='color:var(--muted)'>No certificates found.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APKShield — {_e(r.apk_name)}</title>
<style>
:root{{--bg:#0f172a;--surface:#1e293b;--card:#1e2d45;--border:#334155;
      --text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--font:'Segoe UI',system-ui,sans-serif}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6}}
/* Header */
.hdr{{background:linear-gradient(135deg,#0a1628 0%,#1e3a5f 100%);
      padding:2rem 3rem;border-bottom:2px solid var(--border);
      display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}}
.hdr h1{{font-size:1.8rem;color:var(--accent);letter-spacing:-.5px}}
.hdr .sub{{color:var(--muted);font-size:.85rem;margin-top:.25rem}}
.score-wrap{{text-align:center}}
.score-num{{font-size:3rem;font-weight:800;line-height:1;color:{rc}}}
.score-lbl{{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}
.risk-badge{{display:inline-block;margin-top:.4rem;padding:.4rem 1rem;border-radius:6px;
             font-weight:700;font-size:.9rem;color:#fff;background:{rc}}}
/* Container / grid */
.wrap{{max-width:1280px;margin:0 auto;padding:2rem 1.5rem}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}}
.g3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:2rem}}
@media(max-width:900px){{.g2,.g3{{grid-template-columns:1fr}}}}
/* Cards */
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem}}
.card h2{{font-size:.85rem;color:var(--muted);text-transform:uppercase;
          letter-spacing:1px;margin-bottom:.9rem;font-weight:600}}
.exec-summary p{{font-size:.9rem;margin-bottom:.5rem}}
.exec-summary ul{{margin:.3rem 0 .3rem 1.2rem;font-size:.85rem}}
/* Metadata */
.meta-row{{display:flex;justify-content:space-between;padding:.35rem 0;
           border-bottom:1px solid var(--border);font-size:.85rem}}
.meta-row:last-child{{border-bottom:none}}
.mk{{color:var(--muted)}} .mv{{font-family:monospace;word-break:break-all}}
.hash{{font-family:monospace;font-size:.72rem;background:var(--surface);
       padding:.25rem .5rem;border-radius:4px;color:var(--accent);word-break:break-all;margin:.2rem 0}}
/* Severity summary */
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:2rem}}
.sev-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;
           padding:1rem;text-align:center}}
.sev-num{{font-size:2.2rem;font-weight:800;line-height:1}}
.sev-lbl{{font-size:.65rem;text-transform:uppercase;color:var(--muted);margin-top:.3rem}}
/* Section */
.section{{margin-bottom:2.5rem}}
.sec-title{{font-size:1.1rem;font-weight:700;color:var(--accent);
            padding-bottom:.5rem;border-bottom:2px solid var(--border);margin-bottom:1.25rem}}
/* Findings */
.cat-section{{margin-bottom:1.5rem}}
.cat-title{{font-size:.95rem;color:var(--muted);margin-bottom:.6rem;
            display:flex;align-items:center;gap:.5rem}}
.cat-badge{{background:var(--border);border-radius:10px;padding:.1rem .5rem;font-size:.72rem;color:var(--text)}}
.findings-list{{display:flex;flex-direction:column;gap:.65rem}}
.finding{{padding:.9rem 1.1rem;border-radius:8px;border:1px solid var(--border)}}
.fhdr{{display:flex;align-items:center;flex-wrap:wrap;gap:.45rem;margin-bottom:.45rem}}
.ftitle{{font-size:.92rem;color:var(--text);font-weight:600}}
.sev-badge{{padding:.12rem .45rem;border-radius:4px;color:#fff;
            font-size:.65rem;font-weight:700;text-transform:uppercase;flex-shrink:0}}
.conf-badge{{font-size:.6rem;padding:.1rem .35rem;border-radius:3px;
             border:1px solid currentColor;opacity:.8}}
.tags{{display:flex;gap:.3rem;flex-wrap:wrap}}
.tag{{font-size:.62rem;padding:.1rem .35rem;border-radius:3px;
      border:1px solid var(--border);color:var(--muted)}}
.fdesc{{font-size:.83rem;color:var(--muted);margin-bottom:.4rem}}
.evidence{{background:#0a1628;border:1px solid var(--border);border-radius:4px;
           padding:.4rem .7rem;margin-bottom:.35rem;overflow-x:auto}}
.evidence code{{font-size:.75rem;color:#a5f3fc;font-family:'Courier New',monospace;white-space:pre-wrap;word-break:break-all}}
.floc{{font-size:.75rem;color:var(--muted);margin-bottom:.35rem}}
.cvss-badge{{font-size:.62rem;padding:.1rem .35rem;border-radius:3px;background:var(--surface);color:var(--muted)}}
.fix{{font-size:.8rem;color:#86efac;padding:.4rem .7rem;
      background:rgba(74,222,128,.07);border-radius:4px;border:1px solid rgba(74,222,128,.2)}}
/* OWASP */
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{text-align:left;padding:.55rem .9rem;background:var(--surface);
    color:var(--muted);text-transform:uppercase;font-size:.7rem;letter-spacing:.5px}}
td{{padding:.6rem .9rem;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(255,255,255,.02)}}
/* Permissions / SDKs */
.perm-list{{list-style:none;display:flex;flex-direction:column;gap:.35rem;
            max-height:380px;overflow-y:auto}}
.perm-item{{padding:.35rem .7rem;border-radius:4px;font-size:.8rem;
            display:flex;flex-wrap:wrap;align-items:baseline;gap:.4rem}}
.perm-item.normal{{background:var(--surface);border-left:3px solid var(--border)}}
.pn{{font-family:monospace;color:var(--text);font-size:.78rem;flex:1 1 auto}}
.pd{{font-size:.72rem;color:var(--muted)}}
/* Certs */
.cert-card{{background:var(--surface);border:1px solid var(--border);
            border-radius:8px;padding:.9rem;margin-bottom:.7rem}}
.cert-field{{font-size:.8rem;padding:.15rem 0;color:var(--muted)}}
.cert-field b{{color:var(--text)}}
/* Component list */
.comp-list{{list-style:none;font-size:.78rem;display:flex;flex-direction:column;gap:.25rem;
            max-height:200px;overflow-y:auto}}
.comp-list li{{padding:.2rem .5rem;border-radius:3px;background:var(--surface);
               font-family:monospace;color:var(--muted);word-break:break-all}}
/* Footer */
.footer{{text-align:center;padding:1.5rem;color:var(--muted);font-size:.75rem;
         border-top:1px solid var(--border);margin-top:2rem}}
/* Tabs */
.tab-bar{{display:flex;gap:.5rem;margin-bottom:1.25rem;flex-wrap:wrap}}
.tab{{padding:.4rem .9rem;border-radius:6px;cursor:pointer;font-size:.82rem;
      background:var(--surface);color:var(--muted);border:1px solid var(--border);
      transition:all .15s}}
.tab.active,.tab:hover{{background:var(--accent);color:#0f172a;border-color:var(--accent);font-weight:600}}
</style>
</head>
<body>

<!-- Header -->
<div class="hdr">
  <div>
    <h1>🛡️ APKShield Security Report</h1>
    <div class="sub">Generated: {_e(r.scan_time)} &nbsp;|&nbsp; Duration: {r.duration_secs}s &nbsp;|&nbsp; Tool: APKShield v{r.tool_version}</div>
    <div class="sub" style="margin-top:.2rem;color:var(--text)">{_e(r.apk_name)}</div>
  </div>
  <div class="score-wrap">
    <div class="score-num">{r.risk_score}</div>
    <div class="score-lbl">Risk Score / 100</div>
    <div class="risk-badge">{_e(r.risk_label)}</div>
  </div>
</div>

<div class="wrap">

  <!-- Severity grid -->
  <div class="sev-grid">{sev_cards}</div>

  <!-- Executive summary + metadata -->
  {exec_block}
  <div class="g2" style="margin-top:1.5rem">{meta_left}{meta_right}</div>

  <!-- Findings -->
  <div class="section">
    <div class="sec-title">🔴 Security Findings ({counts['TOTAL']} total)</div>
    {findings_html}
  </div>

  <!-- OWASP Top 10 -->
  <div class="section">
    <div class="sec-title">📊 OWASP Mobile Top 10 Coverage</div>
    <div class="card" style="padding:0;overflow:hidden">
      <table>
        <thead><tr><th>ID</th><th>Category</th><th>Description</th><th>Status</th></tr></thead>
        <tbody>{owasp_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Permissions -->
  <div class="section">
    <div class="sec-title">🔑 Permissions ({len(r.permissions)})</div>
    <div class="card" style="padding:1rem">
      <ul class="perm-list">{perm_items or "<li class='perm-item normal'><span class='pn'>No permissions declared.</span></li>"}</ul>
    </div>
  </div>

  <!-- Components + SDKs -->
  <div class="g3">
    {_component_card("Activities", r.activities)}
    {_component_card("Services / Receivers", r.services + r.receivers)}
    <div class="card" style="padding:1rem">
      <h2>🧩 Third-Party SDKs ({len(r.third_party_sdks)})</h2>
      <ul class="perm-list">{sdk_items}</ul>
    </div>
  </div>

  <!-- Certificates -->
  <div class="section">
    <div class="sec-title">🔐 Signing Certificates</div>
    {cert_section}
  </div>

  <!-- Native libs -->
  {"<div class='section'><div class='sec-title'>📦 Native Libraries (" + str(len(r.native_libs)) + ")</div><div class='card' style='padding:1rem'><ul class='perm-list'>" + "".join(f"<li class='perm-item normal'><span class='pn'>{_e(l)}</span></li>" for l in r.native_libs) + "</ul></div></div>" if r.native_libs else ""}

</div>

<div class="footer">
  APKShield v{_e(r.tool_version)} — Professional Android Security Scanner<br>
  For authorised security assessment only. Handle with care.
</div>
</body>
</html>"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _group_by_category(findings) -> Dict[str, List[Finding]]:
    result: Dict[str, List[Finding]] = {}
    for f in findings:
        result.setdefault(f.category, []).append(f)
    return result


def _meta_card(title: str, pairs) -> str:
    rows = "".join(
        f'<div class="meta-row"><span class="mk">{_e(k)}</span><span class="mv">{_e(str(v))}</span></div>'
        for k, v in pairs
    )
    return f'<div class="card"><h2>{_e(title)}</h2>{rows}</div>'


def _finding_card(f: Finding) -> str:
    sc   = SEV_COLOR.get(f.severity.value, "#888")
    bg   = SEV_BG.get(f.severity.value, "rgba(0,0,0,.1)")
    cc   = CONF_COLOR.get(f.confidence, "#888")
    ev   = f'<div class="evidence"><code>{_e(f.evidence)}</code></div>' if f.evidence else ""
    loc  = f'<div class="floc">📄 {_e(f.file_path)}{":" + str(f.line_number) if f.line_number else ""}</div>' if f.file_path else ""
    cvss = f'<span class="cvss-badge">CVSS {f.cvss:.1f}</span>' if f.cvss else ""
    fix  = f'<div class="fix">💡 <b>Fix:</b> {_e(f.remediation)}</div>' if f.remediation else ""
    owasp_tag = f"<span class='tag'>OWASP {_e(f.owasp)}</span>" if f.owasp else ""
    cwe_tag   = f"<span class='tag'>{_e(f.cwe)}</span>"           if f.cwe   else ""
    return f"""<div class="finding" style="border-left:4px solid {sc};background:{bg}">
  <div class="fhdr">
    <span class="sev-badge" style="background:{sc}">{_e(f.severity.value)}</span>
    <strong class="ftitle">{_e(f.title)}</strong>
    <span class="conf-badge" style="color:{cc}">{_e(f.confidence)}</span>
    {cvss}
    <span class="tags">{owasp_tag}{cwe_tag}</span>
  </div>
  <p class="fdesc">{_e(f.description)}</p>
  {ev}{loc}{fix}
</div>"""


def _component_card(title: str, items: List[str]) -> str:
    li = "".join(
        f'<li>{_e(i.split(".")[-1])}</li>' for i in items[:30]
    )
    extra = f'<li style="color:var(--muted)">…and {len(items)-30} more</li>' if len(items) > 30 else ""
    return f"""<div class="card" style="padding:1rem">
      <h2>{_e(title)} ({len(items)})</h2>
      <ul class="comp-list">{li}{extra}</ul>
    </div>"""
