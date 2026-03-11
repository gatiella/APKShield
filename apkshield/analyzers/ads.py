"""
apkshield/analyzers/ads.py

Ad SDK & Privacy Audit Analyzer
  - Identifies ad networks present in the APK
  - Maps which dangerous permissions each ad SDK needs
  - Flags data collection practices
  - Detects missing consent / GDPR compliance signals
  - Detects ad SDK version vulnerabilities where known
"""
from __future__ import annotations
import os
import re
from typing import Dict, List, Optional, Set

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

# ── Ad SDK database ───────────────────────────────────────────────────────────
# key: package prefix to detect
# value: {name, category, data_collected, required_permissions, privacy_risk, notes}
AD_SDK_DATABASE: Dict[str, dict] = {
    "com.google.android.gms.ads": {
        "name": "Google Mobile Ads (AdMob)",
        "category": "Ad Network",
        "data_collected": [
            "Google Advertising ID (GAID)",
            "Device model, OS version",
            "App usage and interaction data",
            "Location (if ACCESS_FINE_LOCATION granted)",
            "IP address",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "optional_permissions": ["ACCESS_FINE_LOCATION", "READ_PHONE_STATE"],
        "notes": "Largest ad network. Must use UMP SDK for GDPR consent. Requires Privacy Nutrition Label.",
        "consent_api": "Google UMP SDK (UserMessagingPlatform)",
    },
    "com.facebook.ads": {
        "name": "Meta Audience Network",
        "category": "Ad Network",
        "data_collected": [
            "Facebook/Instagram account linkage",
            "Device identifiers (IDFA/AAID)",
            "Behavioral data across Meta properties",
            "Location (approximate)",
            "App events",
        ],
        "privacy_risk": Severity.HIGH,
        "required_permissions": ["INTERNET"],
        "optional_permissions": ["ACCESS_FINE_LOCATION", "READ_PHONE_STATE"],
        "notes": "High privacy risk — cross-app tracking across Meta ecosystem. Requires explicit consent under GDPR.",
        "consent_api": "Meta Privacy SDK",
    },
    "com.unity3d.ads": {
        "name": "Unity Ads",
        "category": "Ad Network / Game Ads",
        "data_collected": [
            "Advertising ID",
            "Device info",
            "Game session data",
            "IP address",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "optional_permissions": [],
        "notes": "Common in mobile games. Must respect user consent for COPPA if targeting children.",
        "consent_api": "Unity Privacy / GDPR API",
    },
    "com.ironsource.mediationsdk": {
        "name": "IronSource",
        "category": "Ad Mediation",
        "data_collected": [
            "Advertising ID",
            "Device fingerprinting data",
            "Ad interaction data",
            "Cross-network attribution data",
        ],
        "privacy_risk": Severity.HIGH,
        "required_permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "optional_permissions": ["ACCESS_FINE_LOCATION", "READ_PHONE_STATE", "BLUETOOTH"],
        "notes": "Mediation layer — routes to multiple ad networks, multiplying data exposure.",
        "consent_api": "IronSource Consent API",
    },
    "com.applovin": {
        "name": "AppLovin",
        "category": "Ad Network / Mediation",
        "data_collected": [
            "Advertising ID",
            "Device hardware info",
            "Network type",
            "App usage",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "optional_permissions": ["ACCESS_FINE_LOCATION"],
        "notes": "Includes MAX mediation. Check consent flow is implemented.",
        "consent_api": "AppLovin Consent Flow",
    },
    "com.chartboost": {
        "name": "Chartboost",
        "category": "Ad Network / Game Ads",
        "data_collected": [
            "Advertising ID",
            "Device info",
            "Game interaction data",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET"],
        "optional_permissions": [],
        "notes": "Popular in casual games. Requires COPPA compliance if app targets children.",
        "consent_api": "Chartboost GDPR API",
    },
    "com.vungle": {
        "name": "Vungle (Liftoff)",
        "category": "Ad Network",
        "data_collected": [
            "Advertising ID",
            "Device info",
            "Video ad engagement data",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET", "ACCESS_NETWORK_STATE"],
        "optional_permissions": ["WRITE_EXTERNAL_STORAGE"],
        "notes": "Video ad specialist. Check WRITE_EXTERNAL_STORAGE usage — no longer needed on Android 10+.",
        "consent_api": "Vungle Privacy API",
    },
    "com.mopub": {
        "name": "MoPub (DEPRECATED)",
        "category": "Ad Mediation",
        "data_collected": ["N/A — deprecated"],
        "privacy_risk": Severity.HIGH,
        "required_permissions": [],
        "optional_permissions": [],
        "notes": "MoPub was shut down March 2023. Any app still using MoPub has an unmaintained SDK with no security patches.",
        "consent_api": "N/A",
    },
    "com.startapp": {
        "name": "StartApp",
        "category": "Ad Network",
        "data_collected": [
            "Device location (aggressive — known for excessive collection)",
            "IMEI / device identifiers",
            "App list on device",
            "WiFi network info",
        ],
        "privacy_risk": Severity.CRITICAL,
        "required_permissions": ["INTERNET", "ACCESS_FINE_LOCATION"],
        "optional_permissions": ["READ_PHONE_STATE", "ACCESS_WIFI_STATE", "BLUETOOTH"],
        "notes": "HIGH RISK — StartApp has faced regulatory action for excessive data collection including location harvesting and device fingerprinting beyond GAID.",
        "consent_api": "StartApp Privacy API (verify consent is enforced)",
    },
    "com.inmobi": {
        "name": "InMobi",
        "category": "Ad Network",
        "data_collected": [
            "Advertising ID",
            "Location data",
            "Device info",
            "Demographic inferences",
        ],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET"],
        "optional_permissions": ["ACCESS_FINE_LOCATION"],
        "notes": "GDPR and CCPA consent integration available. Ensure consent SDK is initialised before ad load.",
        "consent_api": "InMobi Consent API",
    },
    "net.pubnative": {
        "name": "PubNative / Verve",
        "category": "Ad Network",
        "data_collected": ["Advertising ID", "Device info", "Location (contextual)"],
        "privacy_risk": Severity.MEDIUM,
        "required_permissions": ["INTERNET"],
        "optional_permissions": ["ACCESS_FINE_LOCATION"],
        "notes": "Focuses on contextual advertising. Consent required for EU.",
        "consent_api": "Verve Consent",
    },
}

# ── GDPR / consent signals to look for ────────────────────────────────────────
CONSENT_SIGNALS = [
    (r'(?i)(UserMessagingPlatform|UmpRequestParameters)', "Google UMP SDK (GDPR consent)"),
    (r'(?i)ConsentInformation', "Consent Information API"),
    (r'(?i)(gdpr|ccpa|coppa)', "GDPR/CCPA/COPPA reference"),
    (r'(?i)(consent.*dialog|show.*consent|request.*consent)', "Consent dialog implementation"),
    (r'(?i)(OneTrust|TrustArc|Didomi|Usercentrics)', "Third-party CMP (Consent Management Platform)"),
    (r'(?i)AdvertisingIdClient', "Advertising ID client (respects opt-out)"),
    (r'(?i)isLimitAdTrackingEnabled', "Limit Ad Tracking check"),
]

# ── Permissions that ad SDKs commonly abuse ───────────────────────────────────
AD_SENSITIVE_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.ACCESS_WIFI_STATE",
}


class AdsAnalyzer:
    def __init__(self, extracted_dir: str, text_files: List[str], permissions: List[str]):
        self.extracted_dir = extracted_dir
        self.text_files    = text_files
        self.permissions   = permissions
        self.findings: List[Finding]      = []
        self.detected_sdks: List[dict]    = []   # rich SDK info for reporting
        self.consent_signals: List[str]   = []

    def analyze(self) -> None:
        log.info("Ad SDK / privacy audit…")
        self._detect_sdks()
        self._check_consent()
        self._check_ad_permission_scope()
        log.info(
            f"Ads analysis: {len(self.detected_sdks)} ad SDK(s) | "
            f"{len(self.consent_signals)} consent signal(s) | "
            f"{len(self.findings)} finding(s)"
        )

    # ── SDK detection ──────────────────────────────────────────────────────────

    def _detect_sdks(self) -> None:
        seen: Set[str] = set()
        all_content = ""

        for fpath in self.text_files:
            try:
                content = open(fpath, errors="replace").read()
                all_content += content
            except OSError:
                continue

        for pkg_prefix, sdk_info in AD_SDK_DATABASE.items():
            if pkg_prefix not in all_content:
                continue
            name = sdk_info["name"]
            if name in seen:
                continue
            seen.add(name)
            self.detected_sdks.append(sdk_info)

            risk = sdk_info["privacy_risk"]

            # Check if any of the sensitive optional permissions this SDK uses are granted
            granted_sensitive = [
                p for p in sdk_info.get("optional_permissions", [])
                if any(p in granted for granted in self.permissions)
            ]

            evidence_parts = [f"Package: {pkg_prefix}"]
            if granted_sensitive:
                evidence_parts.append(f"Sensitive perms granted: {', '.join(granted_sensitive)}")

            self.findings.append(Finding(
                rule_id=f"ADS_SDK_{name[:20].upper().replace(' ','_').replace('(','').replace(')','').replace('/','_')}",
                category="Ad SDK Privacy Audit",
                severity=risk,
                title=f"Ad SDK Detected: {name}",
                description=(
                    f"{name} collects: {', '.join(sdk_info['data_collected'][:3])}. "
                    f"{sdk_info['notes']}"
                ),
                evidence=" | ".join(evidence_parts),
                owasp="M6",
                cwe="CWE-359",
                confidence="HIGH",
                remediation=(
                    f"Ensure {name} is initialised only after user consent. "
                    f"Use consent API: {sdk_info.get('consent_api', 'vendor-specific')}. "
                    "Declare all data collection in your Play Store data safety form."
                ),
            ))

            # Deprecated SDK — extra critical finding
            if "DEPRECATED" in name or "deprecated" in sdk_info["notes"].lower():
                self.findings.append(Finding(
                    rule_id=f"ADS_DEPRECATED_{name[:20].upper().replace(' ','_')}",
                    category="Ad SDK Privacy Audit",
                    severity=Severity.HIGH,
                    title=f"Deprecated Ad SDK: {name}",
                    description=(
                        f"{name} is deprecated / shut down and receives no security updates. "
                        "Unmaintained SDKs are a supply chain vulnerability."
                    ),
                    evidence=f"Package: {pkg_prefix}",
                    owasp="M2",
                    cwe="CWE-1104",
                    confidence="HIGH",
                    remediation=f"Remove {name} immediately and migrate to an actively maintained ad network.",
                ))

    # ── Consent signal detection ───────────────────────────────────────────────

    def _check_consent(self) -> None:
        if not self.detected_sdks:
            return

        all_content = ""
        for fpath in self.text_files:
            try:
                all_content += open(fpath, errors="replace").read()
            except OSError:
                continue

        found_consent = False
        for pattern, desc in CONSENT_SIGNALS:
            if re.search(pattern, all_content):
                self.consent_signals.append(desc)
                found_consent = True

        if not found_consent:
            self.findings.append(Finding(
                rule_id="ADS_NO_CONSENT_FRAMEWORK",
                category="Ad SDK Privacy Audit",
                severity=Severity.HIGH,
                title="Ad SDKs Present But No Consent Framework Detected",
                description=(
                    f"App contains {len(self.detected_sdks)} ad SDK(s) but no consent "
                    "management implementation was found. Under GDPR (EU), CCPA (California), "
                    "and Google Play's data safety requirements, user consent must be obtained "
                    "before initialising ad SDKs that collect personal data."
                ),
                evidence=f"Ad SDKs: {', '.join(s['name'] for s in self.detected_sdks[:4])}",
                owasp="M6",
                cwe="CWE-359",
                cvss=6.5,
                confidence="MEDIUM",
                remediation=(
                    "Implement Google's User Messaging Platform (UMP) SDK for GDPR consent. "
                    "Delay ad SDK initialisation until consent is confirmed. "
                    "For COPPA, disable personalised ads entirely if app targets children."
                ),
            ))

    # ── Permission scope check ────────────────────────────────────────────────

    def _check_ad_permission_scope(self) -> None:
        if not self.detected_sdks:
            return

        granted_sensitive = [
            p for p in self.permissions if p in AD_SENSITIVE_PERMISSIONS
        ]
        if not granted_sensitive:
            return

        # Check if location in background is granted alongside an ad SDK
        bg_location = "android.permission.ACCESS_BACKGROUND_LOCATION"
        if bg_location in self.permissions:
            self.findings.append(Finding(
                rule_id="ADS_BACKGROUND_LOCATION",
                category="Ad SDK Privacy Audit",
                severity=Severity.CRITICAL,
                title="Background Location Granted With Ad SDKs Present",
                description=(
                    "App requests ACCESS_BACKGROUND_LOCATION and contains ad SDKs. "
                    "Some ad SDKs use background location to build user profiles even when "
                    "the app is not in use. This is a serious privacy violation and may "
                    "violate Google Play policy."
                ),
                evidence=f"Permission: {bg_location} | SDKs: {', '.join(s['name'] for s in self.detected_sdks[:3])}",
                owasp="M6",
                cwe="CWE-359",
                cvss=8.5,
                confidence="HIGH",
                remediation=(
                    "Remove ACCESS_BACKGROUND_LOCATION unless your app's core feature "
                    "requires it (navigation, tracking). Never grant it solely for ad targeting."
                ),
            ))
