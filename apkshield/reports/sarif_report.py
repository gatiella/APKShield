"""
apkshield/reports/sarif_report.py
SARIF 2.1.0 output for GitHub Actions, GitLab CI, VS Code.
"""
from __future__ import annotations
import json
from apkshield.models import ScanResult

SARIF_SEVERITY = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}


def generate(result: ScanResult, output_path: str) -> str:
    rules   = {}
    results = []

    for f in result.findings:
        rid = f.rule_id
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description or f.title},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-','')}.html" if f.cwe else "",
                "properties": {
                    "tags": [f.owasp, f.cwe, f"severity/{f.severity.value}"],
                    "security-severity": str(_cvss_to_sarif(f.cvss, f.severity.value)),
                },
                "defaultConfiguration": {
                    "level": SARIF_SEVERITY.get(f.severity.value, "warning"),
                },
            }

        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file_path or "unknown"},
                "region": {"startLine": f.line_number or 1},
            },
        }
        results.append({
            "ruleId": rid,
            "level": SARIF_SEVERITY.get(f.severity.value, "warning"),
            "message": {"text": f.description or f.title},
            "locations": [loc],
            "properties": {
                "confidence": f.confidence,
                "evidence":   f.evidence[:300],
                "remediation":f.remediation,
                "owasp":      f.owasp,
                "cwe":        f.cwe,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "APKShield",
                    "version": result.tool_version,
                    "informationUri": "https://github.com/apkshield/apkshield",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "apk":     result.apk_name,
                "package": result.package_name,
                "sha256":  result.sha256,
                "risk_score": result.risk_score,
                "risk_label": result.risk_label,
            },
        }],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return output_path


def _cvss_to_sarif(cvss: float, severity: str) -> float:
    """Return CVSS 3.x numeric score for SARIF security-severity."""
    if cvss:
        return round(cvss, 1)
    defaults = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}
    return defaults.get(severity, 0.0)
