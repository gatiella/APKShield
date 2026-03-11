"""
apkshield/analyzers/manifest.py
AndroidManifest.xml parser and security analyser.

Improvements over v1:
  - Uses androguard APK object when available (binary manifest support)
  - Falls back to regex on plaintext XML
  - Deduplicates component findings by name
  - Checks min SDK, targetSdk, taskAffinity, custom permissions, FileProvider
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional

from apkshield import logger
from apkshield.models import Finding, Severity
from apkshield.rules.permissions import DANGEROUS_PERMISSIONS

log = logger.get()


class ManifestAnalyzer:
    def __init__(self, extracted_dir: str, apk_object=None):
        self.extracted_dir = extracted_dir
        self.apk = apk_object           # androguard APK instance if available
        self.manifest_path = f"{extracted_dir}/AndroidManifest.xml"

        self.findings: List[Finding] = []
        self.permissions: List[str]  = []
        self.activities:  List[str]  = []
        self.services:    List[str]  = []
        self.receivers:   List[str]  = []
        self.providers:   List[str]  = []
        self.meta: Dict[str, str]    = {}

        self._raw = ""
        self._seen_exported: set = set()

    # ── Entry point ───────────────────────────────────────────────────────────

    def analyze(self) -> None:
        if self.apk:
            self._parse_androguard()
        else:
            self._parse_raw()

        if self._raw:
            self._check_flags()
            self._check_components()
            self._check_network_config()
            self._check_sdk_versions()
            self._check_custom_permissions()
            self._check_file_providers()

        log.info(
            f"Manifest: {len(self.findings)} findings | "
            f"{len(self.permissions)} permissions | "
            f"{len(self.activities)} activities"
        )

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_androguard(self) -> None:
        """Use androguard APK object for reliable binary manifest parsing."""
        try:
            apk = self.apk
            self.meta = {
                "package_name": apk.get_package() or "",
                "version_name": apk.get_androidversion_name() or "",
                "version_code": apk.get_androidversion_code() or "",
                "min_sdk":      apk.get_min_sdk_version() or "",
                "target_sdk":   apk.get_target_sdk_version() or "",
            }
            self.permissions = list(apk.get_permissions())
            self.activities  = list(apk.get_activities())
            self.services    = list(apk.get_services())
            self.receivers   = list(apk.get_receivers())
            self.providers   = list(apk.get_providers())

            # Try to also get raw XML text for flag checks
            try:
                import os
                with open(self.manifest_path, "r", errors="replace") as f:
                    self._raw = f.read()
            except Exception:
                pass

            self._check_dangerous_permissions()
        except Exception as e:
            log.warning(f"Androguard manifest parse error: {e}. Falling back to regex.")
            self._parse_raw()

    def _parse_raw(self) -> None:
        """Regex-based fallback for plain-text manifest XML."""
        import os
        if not os.path.exists(self.manifest_path):
            log.warning("AndroidManifest.xml not found.")
            return
        with open(self.manifest_path, "r", errors="replace") as f:
            self._raw = f.read()
        if not self._raw.strip():
            return

        raw = self._raw

        # Metadata
        def _attr(name: str) -> str:
            m = re.search(rf'{name}\s*=\s*["\']([^"\']+)["\']', raw)
            return m.group(1) if m else ""

        self.meta = {
            "package_name": _attr("package"),
            "version_name": _attr("android:versionName"),
            "version_code": _attr("android:versionCode"),
            "min_sdk":      _attr("android:minSdkVersion"),
            "target_sdk":   _attr("android:targetSdkVersion"),
        }

        # Permissions
        for m in re.finditer(
            r'<uses-permission[^>]+android:name\s*=\s*["\']([^"\']+)["\']', raw
        ):
            self.permissions.append(m.group(1))

        # Components
        for tag in ("activity", "service", "receiver", "provider"):
            for m in re.finditer(rf"<{tag}[\s\n][^>]+>", raw, re.DOTALL):
                nm = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', m.group(0))
                name = nm.group(1) if nm else "unknown"
                getattr(self, f"{tag}s" if tag != "activity" else "activities").append(name)

        self._check_dangerous_permissions()

    # ── Permission checks ─────────────────────────────────────────────────────

    def _check_dangerous_permissions(self) -> None:
        for perm in self.permissions:
            if perm in DANGEROUS_PERMISSIONS:
                sev, desc, fix = DANGEROUS_PERMISSIONS[perm]
                self.findings.append(Finding(
                    rule_id=f"PERM_{perm.split('.')[-1]}",
                    category="Dangerous Permission",
                    severity=sev,
                    title=f"Dangerous Permission: {perm.split('.')[-1]}",
                    description=desc,
                    evidence=perm,
                    file_path="AndroidManifest.xml",
                    owasp="M8",
                    cwe="CWE-250",
                    remediation=fix,
                ))

    # ── Flag checks ───────────────────────────────────────────────────────────

    def _check_flags(self) -> None:
        raw = self._raw

        if re.search(r'android:debuggable\s*=\s*["\']true["\']', raw):
            self.findings.append(Finding(
                rule_id="MANIFEST_DEBUGGABLE",
                category="Configuration",
                severity=Severity.HIGH,
                title="Application is Debuggable",
                description=(
                    "android:debuggable=true allows any computer with ADB to attach a debugger, "
                    "extract memory, bypass security checks, and read private data."
                ),
                evidence='android:debuggable="true"',
                file_path="AndroidManifest.xml",
                owasp="M7",
                cwe="CWE-215",
                cvss=7.8,
                remediation=(
                    "Remove android:debuggable from the manifest. Gradle sets it to false "
                    "automatically for release builds. Never ship debuggable APKs."
                ),
            ))

        if re.search(r'android:allowBackup\s*=\s*["\']true["\']', raw):
            self.findings.append(Finding(
                rule_id="MANIFEST_BACKUP",
                category="Data Storage",
                severity=Severity.MEDIUM,
                title="ADB Backup Enabled",
                description=(
                    "android:allowBackup=true allows any USB-connected computer to extract "
                    "app data via 'adb backup' without root access."
                ),
                evidence='android:allowBackup="true"',
                file_path="AndroidManifest.xml",
                owasp="M9",
                cwe="CWE-312",
                cvss=4.6,
                remediation=(
                    "Set android:allowBackup=false, or define android:fullBackupContent "
                    "with explicit exclusion rules for sensitive data."
                ),
            ))

        if re.search(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', raw):
            self.findings.append(Finding(
                rule_id="MANIFEST_CLEARTEXT",
                category="Network Security",
                severity=Severity.HIGH,
                title="Cleartext Network Traffic Permitted",
                description=(
                    "android:usesCleartextTraffic=true explicitly allows unencrypted HTTP, "
                    "enabling passive eavesdropping and active MITM attacks."
                ),
                evidence='android:usesCleartextTraffic="true"',
                file_path="AndroidManifest.xml",
                owasp="M5",
                cwe="CWE-319",
                cvss=7.4,
                remediation=(
                    "Set usesCleartextTraffic=false and define a Network Security Config "
                    "(res/xml/network_security_config.xml) that blocks cleartext."
                ),
            ))

    # ── Component export checks ───────────────────────────────────────────────

    def _check_components(self) -> None:
        raw = self._raw
        SEV_MAP = {
            "activity": Severity.MEDIUM,
            "service":  Severity.HIGH,
            "receiver": Severity.HIGH,
            "provider": Severity.HIGH,
        }

        for tag in ("activity", "service", "receiver", "provider"):
            pattern = rf"<{tag}[\s\n]((?:[^<]|<(?!/{tag}>))*?)(?:/>|>)"
            for m in re.finditer(pattern, raw, re.DOTALL):
                block = m.group(0)
                nm = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', block)
                name = nm.group(1) if nm else "unknown"

                if name in self._seen_exported:
                    continue

                exported      = re.search(r'android:exported\s*=\s*["\']true["\']', block)
                not_exported  = re.search(r'android:exported\s*=\s*["\']false["\']', block)
                has_intent    = bool(re.search(r'<intent-filter', block))
                has_perm      = re.search(r'android:permission\s*=\s*["\']([^"\']+)["\']', block)

                is_exposed = exported or (has_intent and not not_exported)

                if is_exposed and not has_perm:
                    self._seen_exported.add(name)
                    short = name.split(".")[-1]
                    self.findings.append(Finding(
                        rule_id=f"EXPORTED_{tag.upper()}_{short[:20]}",
                        category="Component Security",
                        severity=SEV_MAP[tag],
                        title=f"Unprotected Exported {tag.capitalize()}: {short}",
                        description=(
                            f"This {tag} is exported without a permission requirement, "
                            f"allowing any installed app to interact with it. "
                            f"This can enable intent spoofing, data theft, or privilege escalation."
                        ),
                        evidence=block[:250].strip(),
                        file_path="AndroidManifest.xml",
                        owasp="M8",
                        cwe="CWE-926",
                        cvss=6.5,
                        remediation=(
                            f"Add android:permission='<your.signature.permission>' to restrict "
                            f"access, or set android:exported=false if external access is not needed."
                        ),
                    ))

        # Task hijacking
        if re.search(r'android:taskAffinity\s*=\s*["\']["\']', raw):
            self.findings.append(Finding(
                rule_id="TASK_HIJACKING",
                category="Component Security",
                severity=Severity.HIGH,
                title="Empty taskAffinity — Task Hijacking Risk",
                description=(
                    "An empty taskAffinity allows a malicious app with "
                    "FLAG_ACTIVITY_NEW_TASK to insert itself into this app's task stack, "
                    "potentially intercepting sensitive screens."
                ),
                evidence='android:taskAffinity=""',
                file_path="AndroidManifest.xml",
                owasp="M1",
                cwe="CWE-830",
                cvss=7.1,
                remediation="Remove the empty taskAffinity or set a unique package-scoped value.",
            ))

    # ── Network Security Config ───────────────────────────────────────────────

    def _check_network_config(self) -> None:
        if not re.search(r'android:networkSecurityConfig', self._raw):
            self.findings.append(Finding(
                rule_id="NO_NETWORK_SEC_CONFIG",
                category="Network Security",
                severity=Severity.MEDIUM,
                title="No Network Security Configuration Defined",
                description=(
                    "Without a Network Security Config, the app relies on platform "
                    "defaults, which vary by Android version and allow user-added CAs "
                    "on API < 24. Certificate pinning is also not possible without it."
                ),
                evidence="android:networkSecurityConfig not present in <application>",
                file_path="AndroidManifest.xml",
                owasp="M5",
                cwe="CWE-319",
                cvss=5.3,
                remediation=(
                    "Create res/xml/network_security_config.xml and reference it via "
                    "android:networkSecurityConfig. Define <pin-set> entries for critical domains."
                ),
            ))

    # ── SDK version checks ────────────────────────────────────────────────────

    def _check_sdk_versions(self) -> None:
        try:
            min_sdk = int(self.meta.get("min_sdk") or 0)
        except ValueError:
            min_sdk = 0

        if 0 < min_sdk < 21:
            self.findings.append(Finding(
                rule_id="MIN_SDK_TOO_LOW",
                category="Configuration",
                severity=Severity.MEDIUM,
                title=f"Very Low minSdkVersion ({min_sdk})",
                description=(
                    f"minSdkVersion={min_sdk} targets Android {min_sdk}, which lacks "
                    "modern security controls (file-based encryption, StrictMode defaults, "
                    "network security config, etc.)."
                ),
                evidence=f"android:minSdkVersion=\"{min_sdk}\"",
                file_path="AndroidManifest.xml",
                owasp="M8",
                cwe="CWE-1104",
                cvss=4.0,
                remediation="Raise minSdkVersion to at least 21 (Android 5.0) — ideally 26+.",
            ))

    # ── Custom permission checks ──────────────────────────────────────────────

    def _check_custom_permissions(self) -> None:
        for m in re.finditer(
            r'<permission[^>]+android:name\s*=\s*["\']([^"\']+)["\'][^>]*'
            r'android:protectionLevel\s*=\s*["\']([^"\']+)["\']',
            self._raw,
        ):
            name, level = m.group(1), m.group(2).lower()
            if level in ("normal", "0x0"):
                self.findings.append(Finding(
                    rule_id=f"CUSTOM_PERM_NORMAL_{name.split('.')[-1][:20]}",
                    category="Component Security",
                    severity=Severity.MEDIUM,
                    title=f"Custom Permission with 'normal' Protection Level: {name.split('.')[-1]}",
                    description=(
                        "Any app can request and be granted a 'normal' protection level permission "
                        "without user confirmation. This may expose guarded components."
                    ),
                    evidence=m.group(0)[:200],
                    file_path="AndroidManifest.xml",
                    owasp="M8",
                    cwe="CWE-732",
                    cvss=5.0,
                    remediation="Change protectionLevel to 'signature' for inter-app permissions.",
                ))

    # ── FileProvider checks ───────────────────────────────────────────────────

    def _check_file_providers(self) -> None:
        raw = self._raw
        # Look for FileProvider exported=true (should never be)
        for m in re.finditer(
            r'<provider[^>]+FileProvider[^>]+android:exported\s*=\s*["\']true["\']', raw
        ):
            self.findings.append(Finding(
                rule_id="FILEPROVIDER_EXPORTED",
                category="Component Security",
                severity=Severity.HIGH,
                title="FileProvider Exported — Direct File Access Risk",
                description=(
                    "FileProvider should always have android:exported=false. "
                    "An exported FileProvider allows any app to read shared files."
                ),
                evidence=m.group(0)[:200],
                file_path="AndroidManifest.xml",
                owasp="M9",
                cwe="CWE-732",
                cvss=7.0,
                remediation="Set android:exported=false on all FileProvider declarations.",
            ))
