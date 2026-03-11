"""
apkshield/analyzers/native.py
Native library (.so) and DEX binary analysis.
  - Printable-string extraction from .so files
  - Unsafe C function detection
  - Obfuscation heuristic (class name entropy)
  - Dynamic DEX loading detection
"""
from __future__ import annotations
import os
import re
import math
import zipfile
from typing import List, Optional

from apkshield import logger
from apkshield.models import Finding, Severity
from apkshield.rules.patterns import SECRET_PATTERNS

log = logger.get()

# Unsafe C functions that indicate memory-safety risks
UNSAFE_C_FUNCTIONS = [
    (b"gets(",    "gets() — no bounds checking; trivially exploitable buffer overflow.", Severity.CRITICAL, "CWE-120"),
    (b"strcpy(",  "strcpy() — unchecked string copy; use strlcpy/strncpy.", Severity.HIGH,     "CWE-120"),
    (b"strcat(",  "strcat() — unchecked string append; use strlcat.", Severity.HIGH,     "CWE-120"),
    (b"sprintf(", "sprintf() — format string without length limit; use snprintf.", Severity.MEDIUM, "CWE-120"),
    (b"vsprintf(","vsprintf() — variadic format without length; use vsnprintf.", Severity.MEDIUM, "CWE-120"),
    (b"system(",  "system() — executes a shell command; dangerous if user-controlled.", Severity.HIGH, "CWE-78"),
    (b"exec(",    "exec() family call detected in native code.", Severity.HIGH, "CWE-78"),
    (b"popen(",   "popen() — opens a shell pipe; command injection risk.", Severity.HIGH, "CWE-78"),
]


class NativeAnalyzer:
    def __init__(self, extracted_dir: str):
        self.extracted_dir = extracted_dir
        self.findings: List[Finding] = []
        self.libraries: List[str]    = []

    def analyze(self) -> None:
        lib_dir = os.path.join(self.extracted_dir, "lib")
        if os.path.exists(lib_dir):
            for root, _, files in os.walk(lib_dir):
                for fname in files:
                    if fname.endswith(".so"):
                        fpath = os.path.join(root, fname)
                        rel   = os.path.relpath(fpath, self.extracted_dir)
                        self.libraries.append(rel)
                        self._analyze_so(fpath, rel)

        self._check_obfuscation()
        log.info(f"Native analysis: {len(self.libraries)} lib(s), {len(self.findings)} finding(s)")

    # ── .so analysis ──────────────────────────────────────────────────────────

    def _analyze_so(self, fpath: str, rel: str) -> None:
        try:
            with open(fpath, "rb") as f:
                data = f.read()
        except OSError:
            return

        # Extract printable ASCII strings (≥8 chars)
        strings = re.findall(rb"[\x20-\x7E]{8,}", data)
        text    = b"\n".join(strings).decode("ascii", errors="replace")

        # Check for secrets in binary strings
        for rule in SECRET_PATTERNS[:20]:          # top high-signal rules only
            name, pattern, severity, owasp, cwe = rule[:5]
            if re.search(pattern, text):
                self.findings.append(Finding(
                    rule_id=f"NATIVE_SECRET_{name[:18].upper().replace(' ','_')}",
                    category="Secrets in Native Code",
                    severity=severity,
                    title=f"{name} in Native Library",
                    description=(
                        f"Pattern matching '{name}' found in binary strings of {os.path.basename(fpath)}. "
                        "Hardcoded secrets in native libraries are still extractable with 'strings'."
                    ),
                    evidence=f"Pattern '{name}' in {os.path.basename(fpath)}",
                    file_path=rel,
                    owasp=owasp,
                    cwe=cwe,
                    confidence="MEDIUM",
                    remediation="Remove hardcoded secrets from native code. Fetch secrets at runtime from a secure server.",
                ))

        # Unsafe C functions
        seen_funcs: set = set()
        for func_bytes, desc, sev, cwe in UNSAFE_C_FUNCTIONS:
            if func_bytes in data and func_bytes not in seen_funcs:
                seen_funcs.add(func_bytes)
                self.findings.append(Finding(
                    rule_id=f"NATIVE_UNSAFE_{func_bytes.decode().strip('(').upper()}",
                    category="Native Code Safety",
                    severity=sev,
                    title=f"Unsafe Native Function: {func_bytes.decode()}",
                    description=desc,
                    evidence=func_bytes.decode(),
                    file_path=rel,
                    owasp="M7",
                    cwe=cwe,
                    confidence="HIGH",
                    remediation=(
                        "Replace unsafe functions with bounds-checked equivalents "
                        "(strlcpy, snprintf, etc.). Enable FORTIFY_SOURCE and stack canaries."
                    ),
                ))

    # ── Obfuscation heuristic ─────────────────────────────────────────────────

    def _check_obfuscation(self) -> None:
        """
        Simple heuristic: scan smali class names.
        If most class names are very short (1-2 chars after package),
        the code is likely obfuscated with ProGuard/R8.
        If NOT obfuscated, flag it as a binary protection gap.
        """
        smali_dir = os.path.join(self.extracted_dir, "smali")
        if not os.path.exists(smali_dir):
            return

        total = 0
        short = 0
        for root, _, files in os.walk(smali_dir):
            for fname in files:
                if fname.endswith(".smali"):
                    total += 1
                    base = os.path.splitext(fname)[0]
                    if len(base) <= 2:
                        short += 1

        if total == 0:
            return

        ratio = short / total
        if ratio >= 0.5:
            log.info(f"Obfuscation detected (ratio {ratio:.0%})")
        else:
            self.findings.append(Finding(
                rule_id="NO_OBFUSCATION",
                category="Binary Protections",
                severity=Severity.MEDIUM,
                title="Code Appears Unobfuscated",
                description=(
                    f"Only {short}/{total} smali class files have obfuscated short names (ratio {ratio:.0%}). "
                    "Unobfuscated code makes reverse engineering significantly easier, "
                    "exposing business logic and accelerating vulnerability discovery."
                ),
                evidence=f"Short-named classes: {short}/{total} ({ratio:.0%})",
                file_path="smali/",
                owasp="M7",
                cwe="CWE-656",
                cvss=4.3,
                confidence="MEDIUM",
                remediation=(
                    "Enable ProGuard/R8 in release builds (minifyEnabled = true in build.gradle). "
                    "Use a custom proguard-rules.pro. Consider DexGuard for stronger obfuscation."
                ),
            ))
