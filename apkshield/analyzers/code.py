"""
apkshield/analyzers/code.py
Regex-based code scanner for smali, Java, XML, JSON, properties files.

Key improvements over v1:
  - Per-file deduplication (same rule + same line = one finding)
  - HTTP URL false-positive filter (XML namespaces, schema URIs)
  - Placeholder / dummy-value suppression
  - Confidence field propagated from rule definitions
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import List, Set, Tuple

from apkshield import logger
from apkshield.models import Finding, Severity
from apkshield.rules.patterns import (
    SECRET_PATTERNS, NETWORK_PATTERNS, CRYPTO_PATTERNS,
    INJECTION_PATTERNS, STORAGE_PATTERNS, BINARY_PATTERNS,
    PLACEHOLDER_FRAGMENTS, HTTP_WHITELIST, SDK_FINGERPRINTS,
)

log = logger.get()

# Files / directories we always skip
SKIP_PATH_FRAGMENTS = {
    "res/drawable", "res/mipmap", "res/raw",
    "META-INF/", ".png", ".jpg", ".gif", ".webp",
    ".so", ".dex", ".arsc", ".mp3", ".mp4",
}


class CodeScanner:
    def __init__(self, text_files: List[str], base_dir: str):
        self.files    = text_files
        self.base_dir = base_dir
        self.findings: List[Finding] = []
        self.sdks:     List[str]     = []
        self._seen:    Set[Tuple]    = set()

    def scan(self) -> None:
        log.info(f"Scanning {len(self.files)} text files…")
        for fpath in self.files:
            rel = self._rel(fpath)
            if any(skip in rel for skip in SKIP_PATH_FRAGMENTS):
                continue
            try:
                content = Path(fpath).read_text(errors="replace")
            except OSError:
                continue
            lines = content.splitlines()
            self._run_patterns(fpath, rel, content, lines, SECRET_PATTERNS,   "Secrets & Credentials")
            self._run_patterns(fpath, rel, content, lines, NETWORK_PATTERNS,  "Network Security")
            self._run_patterns(fpath, rel, content, lines, CRYPTO_PATTERNS,   "Cryptography")
            self._run_patterns(fpath, rel, content, lines, INJECTION_PATTERNS,"Injection")
            self._run_patterns(fpath, rel, content, lines, STORAGE_PATTERNS,  "Insecure Storage")
            self._run_patterns(fpath, rel, content, lines, BINARY_PATTERNS,   "Binary Protections")
            self._detect_sdks(content)
        log.info(f"Code scan: {len(self.findings)} findings | {len(self.sdks)} SDKs detected")

    # ── Pattern runner ────────────────────────────────────────────────────────

    def _run_patterns(
        self, fpath: str, rel: str, content: str,
        lines: List[str], patterns: list, category: str
    ) -> None:
        for rule in patterns:
            name, pattern, severity, owasp, cwe = rule[:5]
            remediation = rule[5] if len(rule) > 5 else ""
            confidence  = rule[6] if len(rule) > 6 else "MEDIUM"

            for m in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
                evidence = m.group(0)[:200].strip()

                # ── False-positive filters ────────────────────────────────────
                if self._is_placeholder(evidence):
                    continue
                if category == "Network Security" and name == "Cleartext HTTP URL":
                    if self._is_whitelisted_url(evidence):
                        continue

                line_no = content[: m.start()].count("\n") + 1

                # ── Dedup key: same rule + same file + same line ──────────────
                key = (name, rel, line_no)
                if key in self._seen:
                    continue
                self._seen.add(key)

                self.findings.append(Finding(
                    rule_id=f"{category[:6].upper().replace(' ','_')}_{name[:25].upper().replace(' ','_')}",
                    category=category,
                    severity=severity,
                    title=name,
                    description=f"{name} detected.",
                    evidence=evidence,
                    file_path=rel,
                    line_number=line_no,
                    owasp=owasp,
                    cwe=cwe,
                    confidence=confidence,
                    remediation=remediation,
                ))

    # ── SDK detection ─────────────────────────────────────────────────────────

    def _detect_sdks(self, content: str) -> None:
        for pkg_prefix, (sdk_name, _notes) in SDK_FINGERPRINTS.items():
            if pkg_prefix in content and sdk_name not in self.sdks:
                self.sdks.append(sdk_name)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _rel(self, path: str) -> str:
        try:
            return os.path.relpath(path, self.base_dir)
        except ValueError:
            return path

    def _is_placeholder(self, evidence: str) -> bool:
        lower = evidence.lower()
        return any(frag in lower for frag in PLACEHOLDER_FRAGMENTS)

    def _is_whitelisted_url(self, evidence: str) -> bool:
        for domain in HTTP_WHITELIST:
            if domain in evidence:
                return True
        return False
