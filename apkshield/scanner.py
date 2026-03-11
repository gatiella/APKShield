"""
apkshield/scanner.py
Main APKScanner class — orchestrates all analyzers.
"""
from __future__ import annotations
import datetime
import os
import tempfile
import time
import zipfile
from typing import Optional

from apkshield import logger
from apkshield.models import ScanResult, Severity, SEVERITY_ORDER
from apkshield.analyzers.extractor    import APKExtractor, compute_hashes
from apkshield.analyzers.manifest     import ManifestAnalyzer
from apkshield.analyzers.code         import CodeScanner
from apkshield.analyzers.certificate  import CertificateAnalyzer
from apkshield.analyzers.native       import NativeAnalyzer

log = logger.get()


class APKScanner:
    def __init__(
        self,
        apk_path: str,
        output_dir: str = ".",
        verbose: bool = False,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
    ):
        self.apk_path        = os.path.abspath(apk_path)
        self.output_dir      = output_dir
        self.verbose         = verbose
        self.severity_filter = severity_filter
        self.category_filter = category_filter
        self._work_dir       = tempfile.mkdtemp(prefix="apkshield_")
        self.result          = ScanResult()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> ScanResult:
        start = time.monotonic()
        log.info("=" * 62)
        log.info("  APKShield v2.1 — Android Security Scanner")
        log.info("=" * 62)
        log.info(f"Target : {self.apk_path}")

        self._validate()

        r = self.result
        r.apk_path   = self.apk_path
        r.apk_name   = os.path.basename(self.apk_path)
        r.scan_time  = datetime.datetime.now().isoformat()
        r.file_size_bytes = os.path.getsize(self.apk_path)

        # ── Hashes ────────────────────────────────────────────────────────────
        log.info("Computing file hashes…")
        r.sha256, r.sha1, r.md5 = compute_hashes(self.apk_path)
        log.info(f"  SHA-256 : {r.sha256}")
        log.info(f"  SHA-1   : {r.sha1}")
        log.info(f"  MD5     : {r.md5}")

        # ── Extract ───────────────────────────────────────────────────────────
        extractor = APKExtractor(self.apk_path, self._work_dir)
        if not extractor.extract():
            r.errors.append("APK extraction failed")
            return r

        extracted = extractor.extracted_dir

        # ── Androguard APK object (optional, best-effort) ─────────────────────
        apk_obj = self._try_androguard_apk(r)

        # ── Manifest ──────────────────────────────────────────────────────────
        manifest = ManifestAnalyzer(extracted, apk_obj)
        manifest.analyze()
        r.permissions  = manifest.permissions
        r.activities   = manifest.activities
        r.services     = manifest.services
        r.receivers    = manifest.receivers
        r.providers    = manifest.providers
        r.findings.extend(manifest.findings)
        r.is_debuggable = any(f.rule_id == "MANIFEST_DEBUGGABLE" for f in manifest.findings)
        r.allows_backup = any(f.rule_id == "MANIFEST_BACKUP"     for f in manifest.findings)
        if manifest.meta:
            r.package_name = manifest.meta.get("package_name", "")
            r.version_name = manifest.meta.get("version_name", "")
            r.version_code = manifest.meta.get("version_code", "")
            r.min_sdk      = manifest.meta.get("min_sdk",      "")
            r.target_sdk   = manifest.meta.get("target_sdk",   "")

        # ── Code scan ─────────────────────────────────────────────────────────
        code = CodeScanner(extractor.text_files(), extracted)
        code.scan()
        r.findings.extend(code.findings)
        r.third_party_sdks = code.sdks

        # ── Certificate ───────────────────────────────────────────────────────
        cert = CertificateAnalyzer(extracted)
        cert.analyze()
        r.findings.extend(cert.findings)
        r.certificates = cert.certs

        # ── Native libs ───────────────────────────────────────────────────────
        native = NativeAnalyzer(extracted)
        native.analyze()
        r.findings.extend(native.findings)
        r.native_libs    = native.libraries
        r.is_obfuscated  = not any(
            f.rule_id == "NO_OBFUSCATION" for f in native.findings
        ) if native.libraries or self._has_smali(extracted) else None

        # ── Apply user filters ────────────────────────────────────────────────
        if self.severity_filter:
            try:
                min_sev   = Severity(self.severity_filter.upper())
                min_order = SEVERITY_ORDER[min_sev]
                r.findings = [f for f in r.findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
            except ValueError:
                log.warning(f"Invalid severity filter '{self.severity_filter}' — ignored.")

        if self.category_filter:
            cf = self.category_filter.lower()
            r.findings = [f for f in r.findings if cf in f.category.lower()]

        # ── Sort by severity ──────────────────────────────────────────────────
        r.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        r.duration_secs = round(time.monotonic() - start, 2)
        self._log_summary(r)
        return r

    def cleanup(self) -> None:
        import shutil
        try:
            shutil.rmtree(self._work_dir)
        except OSError:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _validate(self) -> None:
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK not found: {self.apk_path}")
        if not zipfile.is_zipfile(self.apk_path):
            raise ValueError(f"Not a valid APK/ZIP file: {self.apk_path}")

    def _try_androguard_apk(self, r: ScanResult):
        try:
            from androguard.core.apk import APK
            apk = APK(self.apk_path)
            # Pre-populate metadata from androguard (more reliable for binary manifests)
            r.package_name = apk.get_package()              or ""
            r.version_name = apk.get_androidversion_name() or ""
            r.version_code = apk.get_androidversion_code() or ""
            r.min_sdk      = apk.get_min_sdk_version()     or ""
            r.target_sdk   = apk.get_target_sdk_version()  or ""
            log.info(f"Package : {r.package_name}  v{r.version_name}  (SDK {r.min_sdk}–{r.target_sdk})")
            return apk
        except Exception as e:
            log.debug(f"Androguard APK init: {e}")
            return None

    def _has_smali(self, extracted: str) -> bool:
        smali_dir = os.path.join(extracted, "smali")
        return os.path.isdir(smali_dir)

    def _log_summary(self, r: ScanResult) -> None:
        counts = r.counts
        log.info("=" * 62)
        log.info(f"Scan complete in {r.duration_secs}s")
        log.info(f"Risk Score : {r.risk_score}/100  ({r.risk_label})")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts[sev]
            if n:
                log.info(f"  {sev:<10}: {n}")
        log.info(f"Total      : {counts['TOTAL']} findings")
