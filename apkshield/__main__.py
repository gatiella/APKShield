#!/usr/bin/env python3
"""
apkshield/__main__.py
CLI entry point — python -m apkshield  OR  ./apkshield.py

Usage:
  python -m apkshield app.apk
  python -m apkshield app.apk -f all -o ./reports -v
  python -m apkshield app.apk -f json,sarif --exit-code
"""
from __future__ import annotations
import argparse
import datetime
import os
import sys

BANNER = r"""
    ___    ____  __ __ _____ __    ___ _________   ____
   /   |  / __ \/ //_// ___// /   /  _/ ____/ /   / __ \
  / /| | / /_/ / ,<   \__ \/ /    / // __/ / /   / / / /
 / ___ |/ ____/ /| | ___/ / /____/ // /___/ /___/ /_/ /
/_/  |_/_/   /_/ |_|/____/_____/___/_____/_____/_____/

  Professional Android APK Security Scanner  v2.1
  ──────────────────────────────────────────────────────
"""

C = {
    "CRITICAL": "\033[91m", "HIGH": "\033[33m", "MEDIUM": "\033[93m",
    "LOW": "\033[92m",      "INFO": "\033[36m",
    "R": "\033[0m", "B": "\033[1m", "D": "\033[2m", "G": "\033[92m",
}
RISK_COL = {
    "CRITICAL RISK": C["CRITICAL"], "HIGH RISK": C["HIGH"],
    "MEDIUM RISK":   C["MEDIUM"],   "LOW RISK":  C["LOW"],
    "MINIMAL RISK":  C["G"],
}


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="apkshield",
        description="APKShield — Professional Android APK Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("apk",            help="Path to the APK file")
    p.add_argument("-f", "--format", default="html",
                   help="Report format(s): json, html, pdf, sarif, all, or comma-separated (default: html)")
    p.add_argument("-o", "--output", default=".",
                   help="Output directory for reports (default: current directory)")
    p.add_argument("-v", "--verbose",      action="store_true", help="Verbose output")
    p.add_argument("--log",                default=None,        help="Log file path")
    p.add_argument("--no-banner",          action="store_true", help="Suppress banner")
    p.add_argument("--severity-filter",    default=None,
                   help="Minimum severity to include: CRITICAL|HIGH|MEDIUM|LOW|INFO")
    p.add_argument("--category-filter",    default=None,
                   help="Only show findings from matching category (partial match)")
    p.add_argument("--exit-code",          action="store_true",
                   help="Exit with code 1 if HIGH or CRITICAL findings present (useful for CI)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.no_banner:
        print(BANNER)

    # ── Logger ────────────────────────────────────────────────────────────────
    from apkshield import logger
    logger.setup(log_file=args.log, verbose=args.verbose)
    log = logger.get()

    # ── Validate input ────────────────────────────────────────────────────────
    if not os.path.isfile(args.apk):
        log.error(f"File not found: {args.apk}")
        sys.exit(1)

    import zipfile
    if not zipfile.is_zipfile(args.apk):
        log.error("Not a valid APK (ZIP) file.")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # ── Formats ───────────────────────────────────────────────────────────────
    fmt = args.format.lower()
    formats = ["json","html","pdf","sarif"] if fmt == "all" else [x.strip() for x in fmt.split(",")]

    # ── Scan ──────────────────────────────────────────────────────────────────
    from apkshield.scanner import APKScanner
    scanner = APKScanner(
        args.apk,
        output_dir=args.output,
        verbose=args.verbose,
        severity_filter=args.severity_filter,
        category_filter=args.category_filter,
    )
    try:
        result = scanner.scan()
    except (FileNotFoundError, ValueError) as e:
        log.error(str(e))
        sys.exit(1)
    except Exception as e:
        log.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)
    finally:
        scanner.cleanup()

    # ── Generate reports ──────────────────────────────────────────────────────
    base = os.path.splitext(os.path.basename(args.apk))[0]
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = os.path.join(args.output, f"{base}_{ts}")

    generated = []

    if "json" in formats:
        from apkshield.reports.json_report import generate as gen_json
        p = gen_json(result, f"{prefix}.json")
        log.info(f"JSON  → {p}")
        generated.append(p)

    if "html" in formats:
        from apkshield.reports.html_report import generate as gen_html
        p = gen_html(result, f"{prefix}.html")
        log.info(f"HTML  → {p}")
        generated.append(p)

    if "pdf" in formats:
        from apkshield.reports.pdf_report import generate as gen_pdf
        p = gen_pdf(result, f"{prefix}.pdf")
        log.info(f"PDF   → {p}")
        generated.append(p)

    if "sarif" in formats:
        from apkshield.reports.sarif_report import generate as gen_sarif
        p = gen_sarif(result, f"{prefix}.sarif")
        log.info(f"SARIF → {p}")
        generated.append(p)

    # ── Console summary ───────────────────────────────────────────────────────
    _print_summary(result)

    print(f"{C['B']}📁 Reports:{C['R']}")
    for p in generated:
        print(f"   {p}")
    print()

    # ── CI exit code ──────────────────────────────────────────────────────────
    if args.exit_code:
        from apkshield.models import Severity
        has_critical = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in result.findings
        )
        sys.exit(1 if has_critical else 0)


def _print_summary(result) -> None:
    counts = result.counts
    rc = RISK_COL.get(result.risk_label, "")

    print(f"\n{C['B']}{'─'*62}{C['R']}")
    print(f"{C['B']}  {result.apk_name}{C['R']}")
    print(f"{'─'*62}")
    print(f"  Package  : {result.package_name or 'unknown'}")
    print(f"  Version  : {result.version_name}  (code {result.version_code})")
    print(f"  SDK      : {result.min_sdk} → {result.target_sdk}")
    print(f"  SHA-256  : {result.sha256[:20]}…")
    print()
    print(f"  {C['B']}Risk Score : {rc}{result.risk_score}/100 — {result.risk_label}{C['R']}")
    print()
    print(f"  {C['B']}Findings:{C['R']}")
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        n   = counts[sev]
        col = C.get(sev,"")
        bar = "█" * min(n, 50)
        print(f"    {col}{sev:<10}{C['R']}  {n:4}  {col}{bar}{C['R']}")
    print(f"\n  Total    : {counts['TOTAL']}  |  SDKs: {len(result.third_party_sdks)}")

    top = result.findings[:6]
    if top:
        print(f"\n  {C['B']}Top findings:{C['R']}")
        for f in top:
            col = C.get(f.severity.value,"")
            print(f"    {col}[{f.severity.value:8}]{C['R']}  {f.title}")

    print(f"{'─'*62}\n")


if __name__ == "__main__":
    main()
