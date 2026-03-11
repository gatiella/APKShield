"""
apkshield/models.py
Shared data models: Finding, ScanResult, Severity
"""
from __future__ import annotations
import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH:     5,
    Severity.MEDIUM:   2,
    Severity.LOW:      1,
    Severity.INFO:     0,
}


@dataclass
class Finding:
    rule_id:     str
    category:   str
    severity:   Severity
    title:      str
    description: str
    evidence:    str  = ""
    file_path:   str  = ""
    line_number: int  = 0
    owasp:       str  = ""
    cwe:         str  = ""
    cvss:        float = 0.0
    confidence:  str  = "HIGH"   # HIGH | MEDIUM | LOW
    remediation: str  = ""
    tags:        List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Certificate:
    file:      str = ""
    subject_cn: str = ""
    issuer_cn:  str = ""
    serial:     str = ""
    algorithm:  str = ""
    not_before: str = ""
    not_after:  str = ""
    key_bits:   int = 0
    is_self_signed: bool = False
    is_expired:     bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    # ── APK identity ──────────────────────────────────────────────
    apk_path:      str = ""
    apk_name:      str = ""
    package_name:  str = ""
    version_name:  str = ""
    version_code:  str = ""
    min_sdk:       str = ""
    target_sdk:    str = ""
    sha256:        str = ""
    md5:           str = ""
    sha1:          str = ""
    file_size_bytes: int = 0

    # ── Scan metadata ─────────────────────────────────────────────
    scan_time:     str   = ""
    duration_secs: float = 0.0
    tool_version:  str   = "2.1.0"

    # ── Findings ──────────────────────────────────────────────────
    findings: List[Finding] = field(default_factory=list)

    # ── Components ────────────────────────────────────────────────
    permissions: List[str]       = field(default_factory=list)
    activities:  List[str]       = field(default_factory=list)
    services:    List[str]       = field(default_factory=list)
    receivers:   List[str]       = field(default_factory=list)
    providers:   List[str]       = field(default_factory=list)
    certificates: List[Certificate] = field(default_factory=list)
    native_libs: List[str]       = field(default_factory=list)
    third_party_sdks: List[str]  = field(default_factory=list)

    # ── Flags ─────────────────────────────────────────────────────
    is_debuggable:   bool = False
    allows_backup:   bool = False
    is_obfuscated:   Optional[bool] = None   # None = unknown

    # ── Errors ────────────────────────────────────────────────────
    errors: List[str] = field(default_factory=list)

    # ── Derived properties ────────────────────────────────────────
    @property
    def file_size_kb(self) -> str:
        return f"{self.file_size_bytes / 1024:.1f} KB"

    @property
    def counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["TOTAL"] = len(self.findings)
        return counts

    @property
    def risk_score(self) -> int:
        raw = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        # Scale: normalise to 0-100, nonlinear
        return min(int((raw / (raw + 20)) * 100) if raw else 0, 100)

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s >= 75: return "CRITICAL RISK"
        if s >= 50: return "HIGH RISK"
        if s >= 25: return "MEDIUM RISK"
        if s >= 5:  return "LOW RISK"
        return "MINIMAL RISK"

    @property
    def owasp_coverage(self) -> Dict[str, dict]:
        from apkshield.rules.owasp import OWASP_MOBILE_TOP10
        result: Dict[str, dict] = {}
        for oid, name in OWASP_MOBILE_TOP10.items():
            hits = [f for f in self.findings if f.owasp == oid]
            result[oid] = {
                "name": name,
                "count": len(hits),
                "max_severity": hits[0].severity.value if hits else None,
            }
        return result

    def to_dict(self) -> dict:
        d = {
            "tool": f"APKShield v{self.tool_version}",
            "scan_time": self.scan_time,
            "duration_seconds": self.duration_secs,
            "apk": {
                "name":         self.apk_name,
                "path":         self.apk_path,
                "package":      self.package_name,
                "version_name": self.version_name,
                "version_code": self.version_code,
                "min_sdk":      self.min_sdk,
                "target_sdk":   self.target_sdk,
                "sha256":       self.sha256,
                "sha1":         self.sha1,
                "md5":          self.md5,
                "file_size":    self.file_size_kb,
                "is_debuggable":   self.is_debuggable,
                "allows_backup":   self.allows_backup,
                "is_obfuscated":   self.is_obfuscated,
            },
            "risk": {
                "score": self.risk_score,
                "label": self.risk_label,
            },
            "summary": self.counts,
            "findings": [f.to_dict() for f in self.findings],
            "owasp_coverage": self.owasp_coverage,
            "components": {
                "permissions": self.permissions,
                "activities":  self.activities,
                "services":    self.services,
                "receivers":   self.receivers,
                "providers":   self.providers,
            },
            "certificates": [c.to_dict() for c in self.certificates],
            "native_libraries": self.native_libs,
            "third_party_sdks": self.third_party_sdks,
            "errors": self.errors,
        }
        return d
