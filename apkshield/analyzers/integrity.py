"""
apkshield/analyzers/integrity.py

In-App Purchase (IAP) Flow Analyzer + Anti-Tampering Checker

IAP checks:
  - Detects Google Play Billing / Amazon IAP usage
  - Checks whether purchase verification is server-side or client-side only
  - Flags client-side receipt validation (trivially bypassable)
  - Detects purchase state checks that could be patched

Anti-tampering checks:
  - Runtime signature verification
  - Root / emulator / debugger detection
  - Play Integrity / SafetyNet attestation
  - Installer package validation
  - Checksum / integrity verification patterns
"""
from __future__ import annotations
import os
import re
from typing import List, Set

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

# ── IAP library signatures ────────────────────────────────────────────────────
IAP_SIGNATURES = {
    "com.android.billingclient":        "Google Play Billing Library",
    "com.android.vending.billing":      "Google Play In-App Billing (legacy AIDL)",
    "com.amazon.device.iap":            "Amazon In-App Purchasing",
    "com.samsung.android.iap":          "Samsung In-App Purchase",
    "com.huawei.iap":                   "Huawei In-App Purchase",
    "io.revenuecat":                    "RevenueCat (IAP management)",
    "com.anjlab.android.iab":           "android-inapp-billing-v3 (3rd party)",
    "org.onepf.oms":                    "OpenIAB (multi-store)",
}

# ── Client-side validation patterns (bad — bypassable) ────────────────────────
CLIENT_SIDE_VALIDATION_PATTERNS = [
    # Checking purchase state in client code
    (r'(?i)purchaseState\s*==\s*[01]',
     "Purchase state comparison in client code — trivially patchable to always return purchased"),
    (r'(?i)\.getPurchaseState\(\)\s*[!=]=',
     "getPurchaseState() comparison in client code — should be server-verified"),
    (r'(?i)PURCHASED|UNSPECIFIED_STATE|PENDING',
     "Purchase state constant in business logic — verify this check is not the sole gate"),
    (r'(?i)verifyPurchase|verifySignature|checkSignature',
     "Local signature verification — RSA verification in-app is bypassable"),
    (r'(?i)base64.*decode.*signature|signature.*base64',
     "Base64-decoded signature in client — local crypto verification is not sufficient"),
    (r'(?i)Security\.verifyPurchase|BillingManager\.verify',
     "Client-side receipt verification method"),
    # Dangerous: checking premium status from local SharedPreferences
    (r'(?i)(isPremium|isPurchased|hasPurchased|isSubscribed|unlocked)\s*=\s*(true|false)',
     "Boolean premium flag set in client code — can be patched or SharedPrefs edited on rooted devices"),
    (r'(?i)getBoolean\s*\(["\'](?:premium|purchased|pro|unlocked|subscription)',
     "Premium status read from SharedPreferences — unprotected on rooted devices"),
]

# ── Server-side validation signals (good) ─────────────────────────────────────
SERVER_VALIDATION_SIGNALS = [
    r'(?i)purchaseToken.*http|http.*purchaseToken',
    r'(?i)verif.*server|server.*verif',
    r'(?i)receipt.*upload|upload.*receipt',
    r'(?i)(retrofit|okhttp|volley|httpurlconnection).*purchas',
    r'(?i)google.*play.*developer.*api',
    r'(?i)revenuecat',      # RevenueCat handles server-side
    r'(?i)/purchases/products|/purchases/subscriptions',  # Play Developer API endpoints
]

# ── Anti-tampering patterns ───────────────────────────────────────────────────
ANTI_TAMPER_PATTERNS = [
    # Signature checks
    (r'(?i)(getPackageInfo.*SIGNATURE|GET_SIGNATURES)',
     "Runtime signature check", "present", Severity.INFO),
    (r'(?i)(signatures\[0\]\.toByteArray|CRC32|signature.*hash)',
     "Signature hash comparison", "present", Severity.INFO),
    # Installer check
    (r'(?i)getInstallerPackageName',
     "Installer source check (detects sideloading)", "present", Severity.INFO),
    # Root detection
    (r'(?i)(RootBeer|isRooted|checkForRoot|detectRoot|/system/xbin/su|/system/bin/su)',
     "Root detection", "present", Severity.INFO),
    # Emulator detection
    (r'(?i)(Build\.FINGERPRINT.*generic|Build\.MODEL.*Emulator|isEmulator)',
     "Emulator detection", "present", Severity.INFO),
    (r'(?i)(goldfish|ranchu|sdk_gphone|generic_x86|vbox86|nox|bluestacks)',
     "Emulator hardware string detection", "present", Severity.INFO),
    # Debugger detection
    (r'(?i)(isDebuggerConnected|Debug\.waitingForDebugger)',
     "Debugger detection", "present", Severity.INFO),
    # Play Integrity / SafetyNet
    (r'(?i)(SafetyNetApi\.attest|IntegrityManager.*requestIntegrityToken)',
     "Play Integrity / SafetyNet attestation", "present", Severity.INFO),
    # Xposed detection
    (r'(?i)(XposedBridge|de\.robv\.android\.xposed|LSPosed)',
     "Xposed / LSPosed framework detection", "present", Severity.INFO),
    # Frida detection
    (r'(?i)(frida|gum-js|linjector|27042)',
     "Frida instrumentation detection", "present", Severity.INFO),
    # /proc checks
    (r'(?i)/proc/self/(maps|status|fd)',
     "/proc filesystem integrity check", "present", Severity.INFO),
]

# ── Missing protection checklist ──────────────────────────────────────────────
REQUIRED_FOR_IAP = {
    "signature_check":   ("Runtime Signature Verification",  Severity.HIGH),
    "root_detection":    ("Root Detection",                   Severity.HIGH),
    "server_validation": ("Server-Side Purchase Validation",  Severity.CRITICAL),
    "integrity_api":     ("Play Integrity / SafetyNet",       Severity.MEDIUM),
}


class IntegrityAnalyzer:
    def __init__(self, extracted_dir: str, text_files: List[str]):
        self.extracted_dir = extracted_dir
        self.text_files    = text_files
        self.findings: List[Finding] = []

        self.iap_libraries: List[str]         = []
        self.has_iap                          = False
        self.server_validation_present        = False
        self.client_side_only_risks: List[str]= []

        # Anti-tamper presence flags
        self.protections: dict = {k: False for k in REQUIRED_FOR_IAP}

    def analyze(self) -> None:
        log.info("IAP flow + anti-tampering analysis…")
        self._detect_iap()
        self._check_anti_tamper()
        if self.has_iap:
            self._check_iap_validation()
            self._flag_missing_iap_protections()
        log.info(
            f"Integrity: IAP={self.has_iap} | "
            f"server_validation={self.server_validation_present} | "
            f"{len(self.findings)} finding(s)"
        )

    # ── IAP detection ─────────────────────────────────────────────────────────

    def _detect_iap(self) -> None:
        all_content = self._read_all()
        for pkg, display in IAP_SIGNATURES.items():
            if pkg in all_content:
                self.iap_libraries.append(display)
                self.has_iap = True
        if self.has_iap:
            log.info(f"  IAP libraries: {', '.join(self.iap_libraries)}")

    # ── IAP validation quality check ──────────────────────────────────────────

    def _check_iap_validation(self) -> None:
        all_content = self._read_all()

        # Check for server-side validation signals
        for pattern in SERVER_VALIDATION_SIGNALS:
            if re.search(pattern, all_content):
                self.server_validation_present = True
                self.protections["server_validation"] = True
                break

        if not self.server_validation_present:
            self.findings.append(Finding(
                rule_id="IAP_NO_SERVER_VALIDATION",
                category="In-App Purchase Security",
                severity=Severity.CRITICAL,
                title="IAP Purchase Validation Appears Client-Side Only",
                description=(
                    "The app uses in-app purchases but no server-side validation signals "
                    "were detected. Client-side purchase validation can be trivially bypassed "
                    "by patching the APK to skip the check, using Frida to hook the result, "
                    "or editing SharedPreferences on rooted devices. "
                    "This allows users to unlock paid content without paying."
                ),
                evidence=f"IAP libraries: {', '.join(self.iap_libraries)}. No server validation signals found.",
                owasp="M3",
                cwe="CWE-602",
                cvss=9.1,
                confidence="MEDIUM",
                remediation=(
                    "Send the purchaseToken to your backend server. "
                    "Verify it against the Google Play Developer API "
                    "(purchases.products.get or purchases.subscriptions.get). "
                    "Only unlock content after server confirmation. "
                    "Never trust the client's claim of purchase status."
                ),
            ))

        # Check for risky client-side patterns
        seen: Set[str] = set()
        for fpath in self.text_files:
            try:
                content = open(fpath, errors="replace").read()
            except OSError:
                continue
            rel = os.path.relpath(fpath, self.extracted_dir)

            for pattern, desc in CLIENT_SIDE_VALIDATION_PATTERNS:
                if re.search(pattern, content) and desc not in seen:
                    seen.add(desc)
                    line_no = 0
                    m = re.search(pattern, content)
                    if m:
                        line_no = content[:m.start()].count("\n") + 1
                    self.client_side_only_risks.append(desc)
                    self.findings.append(Finding(
                        rule_id=f"IAP_CLIENT_{desc[:20].upper().replace(' ','_')}",
                        category="In-App Purchase Security",
                        severity=Severity.HIGH,
                        title=f"Client-Side IAP Pattern: {desc[:60]}",
                        description=(
                            f"{desc}. This pattern indicates purchase logic "
                            "executing on the client, which can be bypassed without server validation."
                        ),
                        evidence=desc,
                        file_path=rel,
                        line_number=line_no,
                        owasp="M3",
                        cwe="CWE-602",
                        cvss=8.0,
                        confidence="MEDIUM",
                        remediation=(
                            "Move all purchase state decisions to a trusted server. "
                            "Never store premium status in SharedPreferences without encryption and server sync."
                        ),
                    ))

    # ── Anti-tamper pattern scan ───────────────────────────────────────────────

    def _check_anti_tamper(self) -> None:
        all_content = self._read_all()
        detected: List[str] = []

        for pattern, desc, _, sev in ANTI_TAMPER_PATTERNS:
            if re.search(pattern, all_content, re.IGNORECASE):
                detected.append(desc)
                # Map to protection flags
                if "signature" in desc.lower():
                    self.protections["signature_check"] = True
                if "root" in desc.lower():
                    self.protections["root_detection"] = True
                if "integrity" in desc.lower() or "safetynet" in desc.lower():
                    self.protections["integrity_api"] = True

        if detected:
            self.findings.append(Finding(
                rule_id="INTEGRITY_PROTECTIONS_PRESENT",
                category="Anti-Tampering",
                severity=Severity.INFO,
                title=f"Anti-Tampering Protections Detected ({len(detected)})",
                description=(
                    "The following runtime integrity checks were found: "
                    + ", ".join(detected[:8]) + "."
                ),
                evidence="\n".join(detected[:8]),
                owasp="M7",
                cwe="CWE-693",
                confidence="MEDIUM",
                remediation=(
                    "Ensure protections run at app startup, not just at sensitive actions. "
                    "Verify Play Integrity verdict server-side — never trust client self-report."
                ),
            ))
        else:
            self.findings.append(Finding(
                rule_id="INTEGRITY_NO_PROTECTIONS",
                category="Anti-Tampering",
                severity=Severity.HIGH,
                title="No Anti-Tampering Protections Detected",
                description=(
                    "No runtime integrity checks were found. The app cannot detect "
                    "if it has been repackaged, if it's running on a rooted device, "
                    "or if a debugger / Frida is attached."
                ),
                evidence="No signature check, root detection, or Play Integrity calls found",
                owasp="M7",
                cwe="CWE-693",
                cvss=7.5,
                confidence="MEDIUM",
                remediation=(
                    "Implement: (1) Play Integrity API for device attestation, "
                    "(2) runtime signature check via getPackageInfo, "
                    "(3) root detection, (4) Frida port scan. "
                    "Verify all results server-side."
                ),
            ))

    # ── Missing IAP protection gap findings ───────────────────────────────────

    def _flag_missing_iap_protections(self) -> None:
        for key, (name, sev) in REQUIRED_FOR_IAP.items():
            if not self.protections[key]:
                self.findings.append(Finding(
                    rule_id=f"IAP_MISSING_{key.upper()}",
                    category="In-App Purchase Security",
                    severity=sev,
                    title=f"IAP Present But Missing: {name}",
                    description=(
                        f"The app has in-app purchases ({', '.join(self.iap_libraries[:2])}) "
                        f"but no {name} was detected. "
                        "Without this protection, purchase bypasses are easier."
                    ),
                    evidence=f"IAP: {', '.join(self.iap_libraries[:2])}",
                    owasp="M7" if "validation" not in key else "M3",
                    cwe="CWE-693" if "validation" not in key else "CWE-602",
                    confidence="MEDIUM",
                    remediation=f"Add {name} to protect IAP flows.",
                ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _read_all(self) -> str:
        content = ""
        for fpath in self.text_files:
            try:
                content += open(fpath, errors="replace").read()
            except OSError:
                pass
        return content
