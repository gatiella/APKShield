"""
apkshield/analyzers/dynamic.py

Dynamic Analysis Resistance Analyzer
Detects whether the app is hardened against:
  - Frida instrumentation
  - Xposed / LSPosed framework hooks
  - SSL unpinning tools (Objection, apk-mitm, TrustMeAlready)
  - Dynamic code patching
  - Instrumentation detection bypasses

Also checks for presence of runtime protection mechanisms.
"""
from __future__ import annotations
import os
import re
from typing import List

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

# ── Frida detection signatures ────────────────────────────────────────────────
FRIDA_SIGNATURES = [
    # Frida server port / gadget
    rb"frida",
    rb"gum-js-loop",
    rb"gmain",
    rb"linjector",
    rb"frida-agent",
    rb"frida-gadget",
    # Frida default port strings
    rb"27042",
    rb"27043",
]

# ── Xposed / LSPosed signatures ───────────────────────────────────────────────
XPOSED_SIGNATURES = [
    rb"de.robv.android.xposed",
    rb"XposedBridge",
    rb"XposedHelpers",
    rb"EdXposed",
    rb"LSPosed",
]

# ── SSL unpinning tool signatures ─────────────────────────────────────────────
UNPINNING_SIGNATURES = [
    rb"objection",
    rb"TrustMeAlready",
    rb"apk-mitm",
    rb"ssl_log",
    rb"universal-android-ssl-pinning-bypass",
    rb"SSLUnpinning",
]

# ── Code-level Frida / instrumentation detection patterns (smali / Java) ─────
FRIDA_DETECT_CODE_PATTERNS = [
    # App is CHECKING for Frida (good — shows hardening)
    (r'(?i)(frida|gum[-_]js|linjector|frida[-_]agent|frida[-_]gadget)', "Frida detection logic", True),
    (r'(?i)(xposed|xposedbridge|lsposed|edxposed)', "Xposed detection logic", True),
    # Checking /proc/maps for injected libraries
    (r'(?i)/proc/self/maps', "Reads /proc/self/maps (injection detection)", True),
    (r'(?i)/proc/self/fd', "Reads /proc/self/fd (instrumentation detection)", True),
    # Port scanning for Frida server
    (r'(?i)(27042|27043)', "Scanning for Frida server port", True),
    # Checking loaded libraries
    (r'(?i)(dlopen|dlsym|/proc/self/mem)', "Native library introspection", True),
]

# ── SSL unpinning bypass patterns (app is VULNERABLE to these) ───────────────
UNPINNING_BYPASS_PATTERNS = [
    (r'(?i)okhttp.*\.newbuilder\(\)(?!.*certificatepinner)', "OkHttp client without CertificatePinner", Severity.HIGH),
    (r'(?i)trustmanager.*(?:getacceptedissuers|checksertrusted).*return.*null', "Null TrustManager implementation", Severity.CRITICAL),
    (r'(?i)hostnameverifier.*return.*true', "HostnameVerifier always returns true", Severity.CRITICAL),
    (r'(?i)x509trustmanager', "Custom X509TrustManager (verify implementation)", Severity.MEDIUM),
    (r'(?i)certificatepinner', "CertificatePinner present (good — pinning implemented)", None),  # None = positive signal
    (r'(?i)trustkit', "TrustKit pinning library detected (good)", None),
    (r'(?i)conscrypt', "Conscrypt TLS provider (modern TLS implementation)", None),
]


class DynamicAnalyzer:
    def __init__(self, extracted_dir: str, text_files: List[str]):
        self.extracted_dir = extracted_dir
        self.text_files    = text_files
        self.findings: List[Finding] = []

        # Results
        self.frida_detection_present    = False
        self.xposed_detection_present   = False
        self.cert_pinning_present       = False
        self.anti_debug_present         = False
        self.root_detection_present     = False
        self.emulator_detection_present = False

    def analyze(self) -> None:
        log.info("Dynamic resistance analysis…")
        self._scan_code_patterns()
        self._scan_native_libs()
        self._check_missing_protections()
        log.info(
            f"Dynamic analysis: {len(self.findings)} finding(s) | "
            f"Frida detection: {self.frida_detection_present} | "
            f"Cert pinning: {self.cert_pinning_present}"
        )

    # ── Code pattern scan ─────────────────────────────────────────────────────

    def _scan_code_patterns(self) -> None:
        seen = set()
        for fpath in self.text_files:
            try:
                content = open(fpath, errors="replace").read()
            except OSError:
                continue

            rel = os.path.relpath(fpath, self.extracted_dir)

            # ── Detection presence checks (POSITIVE signals) ──────────────────
            for pattern, desc, is_detection in FRIDA_DETECT_CODE_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    key = pattern[:30]
                    if key in seen:
                        continue
                    seen.add(key)
                    if "frida" in desc.lower():
                        self.frida_detection_present = True
                    if "xposed" in desc.lower():
                        self.xposed_detection_present = True
                    if "/proc" in desc.lower() or "injection" in desc.lower() or "library" in desc.lower():
                        self.anti_debug_present = True

            # ── Anti-debug / integrity checks ─────────────────────────────────
            ad_patterns = [
                (r'isDebuggerConnected\s*\(\s*\)',         "Debugger connection check"),
                (r'android\.os\.Debug\.waitingForDebugger', "Debug wait check"),
                (r'getRuntime\(\)\.totalMemory\(\)',        "Memory anomaly check (emulator detection)"),
                (r'Build\.FINGERPRINT',                     "Build fingerprint check (emulator detection)"),
                (r'Build\.MANUFACTURER',                    "Manufacturer check (emulator detection)"),
                (r'(?i)(goldfish|ranchu|generic_x86|sdk_gphone)', "Emulator hardware string check"),
                (r'RootBeer|isRooted\(\)|checkForRoot',     "Root detection call"),
                (r'SafetyNetClient|PlayIntegrityClient',    "Play Integrity / SafetyNet check"),
                (r'getPackageInfo.*SIGNATURE',              "Signature integrity check"),
                (r'Signature.*getPackageInfo',              "Signature integrity check"),
            ]
            for pattern, desc in ad_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    key = f"ad_{pattern[:20]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    if "root" in desc.lower():
                        self.root_detection_present = True
                    if "emulator" in desc.lower():
                        self.emulator_detection_present = True
                    if "debug" in desc.lower():
                        self.anti_debug_present = True
                    if "signature" in desc.lower():
                        # Signature check is particularly important
                        self.findings.append(Finding(
                            rule_id="DYNAMIC_SIG_CHECK",
                            category="Dynamic Analysis Resistance",
                            severity=Severity.INFO,
                            title="Runtime Signature Integrity Check Detected",
                            description=(
                                "App verifies its own signature at runtime. "
                                "This helps detect APK repackaging and tampering."
                            ),
                            evidence=desc,
                            file_path=rel,
                            owasp="M7",
                            cwe="CWE-693",
                            confidence="HIGH",
                            remediation="Ensure check is server-side validated too — local checks can be patched.",
                        ))

            # ── SSL unpinning vulnerability patterns ──────────────────────────
            for pattern, desc, sev in UNPINNING_BYPASS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    key = f"ssl_{pattern[:20]}"
                    if key in seen:
                        continue
                    seen.add(key)
                    if sev is None:
                        # Positive signal
                        if "certificatepinner" in pattern.lower() or "trustkit" in pattern.lower():
                            self.cert_pinning_present = True
                        continue
                    line_no = content[: re.search(pattern, content, re.IGNORECASE).start()].count("\n") + 1
                    self.findings.append(Finding(
                        rule_id=f"DYNAMIC_SSL_{pattern[:15].upper().replace('(?I)','').replace(' ','_')}",
                        category="Dynamic Analysis Resistance",
                        severity=sev,
                        title=f"SSL Pinning Bypass Risk: {desc}",
                        description=(
                            f"{desc}. Tools like Objection, apk-mitm, and TrustMeAlready "
                            "can intercept HTTPS traffic if pinning is absent or bypassable."
                        ),
                        evidence=desc,
                        file_path=rel,
                        line_number=line_no,
                        owasp="M5",
                        cwe="CWE-295",
                        cvss=7.4,
                        confidence="MEDIUM",
                        remediation=(
                            "Implement OkHttp CertificatePinner or use TrustKit. "
                            "Pin the leaf certificate AND intermediate CA. "
                            "Add backup pins for certificate rotation."
                        ),
                    ))

    # ── Native lib scan for instrumentation signatures ────────────────────────

    def _scan_native_libs(self) -> None:
        lib_dir = os.path.join(self.extracted_dir, "lib")
        if not os.path.exists(lib_dir):
            return

        for root, _, files in os.walk(lib_dir):
            for fname in files:
                if not fname.endswith(".so"):
                    continue
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, self.extracted_dir)
                try:
                    data = open(fpath, "rb").read()
                except OSError:
                    continue

                # Check if THIS is a Frida gadget embedded in the app
                frida_hits = sum(1 for sig in FRIDA_SIGNATURES if sig in data.lower())
                if frida_hits >= 2:
                    self.findings.append(Finding(
                        rule_id="DYNAMIC_FRIDA_GADGET_EMBEDDED",
                        category="Dynamic Analysis Resistance",
                        severity=Severity.CRITICAL,
                        title=f"Frida Gadget Possibly Embedded: {fname}",
                        description=(
                            f"{fname} contains multiple Frida signatures. "
                            "This may be a Frida gadget embedded by a repackager to enable runtime manipulation."
                        ),
                        evidence=f"{frida_hits} Frida signature(s) in {fname}",
                        file_path=rel,
                        owasp="M7",
                        cwe="CWE-693",
                        cvss=9.1,
                        confidence="MEDIUM",
                        remediation=(
                            "Verify this library is legitimate. "
                            "If you did not include a Frida gadget, the APK may have been repackaged."
                        ),
                    ))

                xposed_hits = sum(1 for sig in XPOSED_SIGNATURES if sig in data.lower())
                if xposed_hits >= 2:
                    self.findings.append(Finding(
                        rule_id="DYNAMIC_XPOSED_EMBEDDED",
                        category="Dynamic Analysis Resistance",
                        severity=Severity.HIGH,
                        title=f"Xposed Module Signatures in: {fname}",
                        description=(
                            f"{fname} contains Xposed framework signatures. "
                            "This may indicate an Xposed module was injected into this APK."
                        ),
                        evidence=f"{xposed_hits} Xposed signature(s) in {fname}",
                        file_path=rel,
                        owasp="M7",
                        cwe="CWE-693",
                        cvss=8.0,
                        confidence="MEDIUM",
                        remediation="Verify the library is from your build. Check APK signing integrity.",
                    ))

    # ── Missing protection checks ─────────────────────────────────────────────

    def _check_missing_protections(self) -> None:
        if not self.cert_pinning_present:
            self.findings.append(Finding(
                rule_id="DYNAMIC_NO_CERT_PINNING",
                category="Dynamic Analysis Resistance",
                severity=Severity.HIGH,
                title="Certificate Pinning Not Detected",
                description=(
                    "No certificate pinning implementation was found (CertificatePinner, TrustKit, "
                    "or network_security_config pins). Without pinning, SSL traffic can be intercepted "
                    "by tools like Burp Suite, mitmproxy, Objection, or apk-mitm on any device "
                    "where a CA certificate has been installed."
                ),
                evidence="No CertificatePinner / TrustKit / pin-set found",
                owasp="M5",
                cwe="CWE-295",
                cvss=7.4,
                confidence="HIGH",
                remediation=(
                    "Implement certificate pinning via: (1) OkHttp CertificatePinner, "
                    "(2) Network Security Config <pin-set>, or (3) TrustKit-Android. "
                    "Pin the SPKI hash of your leaf cert with a backup pin on the CA."
                ),
            ))

        if not self.frida_detection_present:
            self.findings.append(Finding(
                rule_id="DYNAMIC_NO_FRIDA_DETECT",
                category="Dynamic Analysis Resistance",
                severity=Severity.MEDIUM,
                title="No Frida Instrumentation Detection",
                description=(
                    "The app does not appear to check for Frida, the most widely used "
                    "runtime instrumentation framework. Frida allows attackers to hook methods, "
                    "bypass authentication, extract keys, and manipulate in-app purchase flows "
                    "at runtime without modifying the APK."
                ),
                evidence="No Frida detection patterns found",
                owasp="M7",
                cwe="CWE-693",
                cvss=6.5,
                confidence="MEDIUM",
                remediation=(
                    "Check for Frida by: scanning /proc/self/maps for frida-agent, "
                    "detecting port 27042, checking loaded SO names for 'frida'. "
                    "Consider using a hardening SDK (DexGuard, Guardsquare) for production."
                ),
            ))

        if not self.root_detection_present:
            self.findings.append(Finding(
                rule_id="DYNAMIC_NO_ROOT_DETECT",
                category="Dynamic Analysis Resistance",
                severity=Severity.MEDIUM,
                title="No Root Detection",
                description=(
                    "App does not check for device root status. On rooted devices, "
                    "attackers can read private app storage, memory dumps, bypass "
                    "security controls, and run Frida without restrictions."
                ),
                evidence="No RootBeer / isRooted / Play Integrity calls found",
                owasp="M7",
                cwe="CWE-693",
                cvss=5.5,
                confidence="MEDIUM",
                remediation=(
                    "Use Google Play Integrity API (replaces SafetyNet). "
                    "Check for su binary, test-keys build, and known root package names. "
                    "Consider RootBeer library for multi-vector detection."
                ),
            ))

        if not self.anti_debug_present:
            self.findings.append(Finding(
                rule_id="DYNAMIC_NO_ANTIDEBUG",
                category="Dynamic Analysis Resistance",
                severity=Severity.LOW,
                title="No Anti-Debug Checks",
                description=(
                    "No debugger detection was found. A debugger attached to the app "
                    "can step through logic, modify variables, and extract sensitive data."
                ),
                evidence="No isDebuggerConnected / Debug.waitingForDebugger found",
                owasp="M7",
                cwe="CWE-693",
                cvss=4.3,
                confidence="LOW",
                remediation=(
                    "Call android.os.Debug.isDebuggerConnected() at critical points. "
                    "Use native ptrace() anti-attach in security-sensitive code paths."
                ),
            ))
