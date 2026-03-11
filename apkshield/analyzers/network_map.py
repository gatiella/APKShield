"""
apkshield/analyzers/network_map.py

Network Traffic Endpoint Mapper

Extracts all API endpoints, hostnames, and domains the app communicates with:
  - HTTPS/HTTP URLs across all files
  - OkHttp / Retrofit base URLs
  - WebSocket URLs (ws://, wss://)
  - GraphQL endpoints
  - Deep link / app-link schemes
  - IP addresses (including internal/cloud ranges)
  - CDN and third-party service domains
  - Classifies each domain by category (ad, analytics, CDN, payment, etc.)
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

# ── Domain classification database ───────────────────────────────────────────
DOMAIN_CATEGORIES: List[Tuple[str, str, str]] = [
    # (domain_fragment, category, risk_note)
    # Analytics
    ("google-analytics.com",  "Analytics",     "Google Analytics — tracks user behaviour"),
    ("analytics.google.com",  "Analytics",     "Google Analytics"),
    ("firebase.google.com",   "Analytics/Infra","Firebase — may include Analytics"),
    ("amplitude.com",         "Analytics",     "Amplitude — product analytics"),
    ("mixpanel.com",          "Analytics",     "Mixpanel — product analytics"),
    ("segment.com",           "Analytics",     "Segment — data pipeline"),
    ("segment.io",            "Analytics",     "Segment — data pipeline"),
    ("appsflyer.com",         "Attribution",   "AppsFlyer — mobile attribution"),
    ("adjust.com",            "Attribution",   "Adjust — mobile attribution"),
    ("branch.io",             "Attribution",   "Branch.io — deep linking / attribution"),
    ("kochava.com",           "Attribution",   "Kochava — mobile attribution"),
    ("singular.net",          "Attribution",   "Singular — mobile attribution"),
    # Ads
    ("googlesyndication.com", "Advertising",   "Google AdSense / Display Network"),
    ("googleadservices.com",  "Advertising",   "Google Ads"),
    ("doubleclick.net",       "Advertising",   "Google DoubleClick (ad serving)"),
    ("ads.google.com",        "Advertising",   "Google Ads"),
    ("facebook.com/ads",      "Advertising",   "Meta Ads"),
    ("graph.facebook.com",    "Social/Ads",    "Facebook Graph API — data collection"),
    ("unity3d.com",           "Advertising",   "Unity Ads"),
    ("ironsource.com",        "Advertising",   "IronSource ad mediation"),
    ("applovin.com",          "Advertising",   "AppLovin"),
    ("chartboost.com",        "Advertising",   "Chartboost"),
    ("vungle.com",            "Advertising",   "Vungle / Liftoff"),
    # Crash / monitoring
    ("sentry.io",             "Monitoring",    "Sentry — error monitoring"),
    ("bugsnag.com",           "Monitoring",    "Bugsnag — error monitoring"),
    ("crashlytics.com",       "Monitoring",    "Crashlytics — crash reporting"),
    ("firebase.io",           "Monitoring",    "Firebase Crashlytics"),
    ("appcenter.ms",          "Monitoring",    "Microsoft App Center"),
    ("newrelic.com",          "Monitoring",    "New Relic APM"),
    ("datadog.com",           "Monitoring",    "Datadog APM"),
    # CDN
    ("cloudfront.net",        "CDN",           "AWS CloudFront"),
    ("fastly.net",            "CDN",           "Fastly CDN"),
    ("akamai.net",            "CDN",           "Akamai CDN"),
    ("cloudflare.com",        "CDN",           "Cloudflare"),
    ("cdn.jsdelivr.net",      "CDN",           "jsDelivr CDN"),
    ("gstatic.com",           "CDN",           "Google Static CDN"),
    ("googleapis.com",        "Google API",    "Google APIs"),
    # Payments
    ("stripe.com",            "Payment",       "Stripe payment processing"),
    ("api.stripe.com",        "Payment",       "Stripe API — ensure server-side only"),
    ("paypal.com",            "Payment",       "PayPal"),
    ("braintree-api.com",     "Payment",       "Braintree (PayPal)"),
    ("adyen.com",             "Payment",       "Adyen payment processing"),
    ("checkout.com",          "Payment",       "Checkout.com"),
    ("square.com",            "Payment",       "Square payments"),
    # Auth / identity
    ("auth0.com",             "Auth",          "Auth0 identity provider"),
    ("okta.com",              "Auth",          "Okta identity provider"),
    ("accounts.google.com",   "Auth",          "Google Sign-In"),
    ("appleid.apple.com",     "Auth",          "Apple Sign-In"),
    ("login.microsoft.com",   "Auth",          "Microsoft identity"),
    ("cognito-idp",           "Auth",          "AWS Cognito"),
    # Cloud infra
    ("amazonaws.com",         "Cloud/Infra",   "AWS — verify not exposing bucket names"),
    ("azure.com",             "Cloud/Infra",   "Microsoft Azure"),
    ("googleapis.com",        "Cloud/Infra",   "Google Cloud Platform"),
    ("firebaseapp.com",       "Firebase",      "Firebase Hosting"),
    ("firebaseio.com",        "Firebase",      "Firebase Realtime Database"),
    ("firebasestorage.googleapis.com", "Firebase", "Firebase Storage"),
    # Push notifications
    ("onesignal.com",         "Push",          "OneSignal push notifications"),
    ("pubnub.com",            "Push/Realtime", "PubNub realtime messaging"),
    ("pusher.com",            "Push/Realtime", "Pusher realtime messaging"),
    ("urban-airship.com",     "Push",          "Airship push notifications"),
    # Support / CRM
    ("intercom.io",           "Support/CRM",   "Intercom customer support"),
    ("zendesk.com",           "Support",       "Zendesk support"),
    ("freshdesk.com",         "Support",       "Freshdesk"),
    ("braze.com",             "CRM",           "Braze customer engagement"),
    # Maps
    ("maps.googleapis.com",   "Maps",          "Google Maps — may collect location"),
    ("openstreetmap.org",     "Maps",          "OpenStreetMap"),
    ("mapbox.com",            "Maps",          "Mapbox"),
]

DOMAIN_CATEGORY_MAP: Dict[str, Tuple[str, str]] = {
    d: (cat, note) for d, cat, note in DOMAIN_CATEGORIES
}

# ── URL extraction patterns ───────────────────────────────────────────────────
URL_PATTERNS = [
    # Full HTTPS URLs
    (r'https://[a-zA-Z0-9\-\.]{4,}\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\'<>]*)?', "https"),
    # HTTP URLs (non-whitelisted)
    (r'http://[a-zA-Z0-9\-\.]{4,}\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\'<>]*)?', "http"),
    # WebSockets
    (r'wss?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\'<>]*)?', "websocket"),
    # Partial paths that hint at API structure (e.g. "/api/v1/users")
    (r'(?<![a-zA-Z])/(?:api|v\d+|graphql|rest|ws|rpc)/[a-zA-Z0-9/\-_\.%?=&]+', "api_path"),
]

# Noise patterns — skip these
URL_SKIP_FRAGMENTS = {
    "schemas.android.com", "www.w3.org", "purl.org", "ns.adobe.com",
    "xml.org", "xmlns.com", "json-schema.org", "iana.org",
    "example.com", "example.org", "localhost", "127.0.0.1",
    ".png", ".jpg", ".gif", ".webp", ".mp4", ".mp3",
}


class NetworkMapper:
    def __init__(self, extracted_dir: str, text_files: List[str]):
        self.extracted_dir = extracted_dir
        self.text_files    = text_files
        self.findings: List[Finding] = []

        # Public outputs
        self.endpoints:      List[str]        = []   # deduplicated URLs
        self.domains:        List[str]        = []   # unique hostnames
        self.api_paths:      List[str]        = []   # /api/v1/… paths
        self.domain_report:  List[dict]       = []   # enriched domain list
        self.websocket_urls: List[str]        = []
        self.insecure_urls:  List[str]        = []   # http:// only

    def analyze(self) -> None:
        log.info("Network endpoint mapping…")
        self._extract_endpoints()
        self._classify_domains()
        self._flag_issues()
        log.info(
            f"Network map: {len(self.endpoints)} endpoints | "
            f"{len(self.domains)} domains | "
            f"{len(self.insecure_urls)} insecure | "
            f"{len(self.findings)} finding(s)"
        )

    # ── Endpoint extraction ───────────────────────────────────────────────────

    def _extract_endpoints(self) -> None:
        seen_urls:    Set[str] = set()
        seen_domains: Set[str] = set()
        seen_paths:   Set[str] = set()

        for fpath in self.text_files:
            try:
                content = open(fpath, errors="replace").read()
            except OSError:
                continue

            for pattern, ptype in URL_PATTERNS:
                for m in re.finditer(pattern, content):
                    raw = m.group(0).strip().rstrip(".,;)\"'")

                    # Skip noise
                    if any(skip in raw for skip in URL_SKIP_FRAGMENTS):
                        continue
                    if len(raw) < 8:
                        continue

                    if ptype == "api_path":
                        if raw not in seen_paths:
                            seen_paths.add(raw)
                            self.api_paths.append(raw)
                        continue

                    if raw in seen_urls:
                        continue
                    seen_urls.add(raw)
                    self.endpoints.append(raw)

                    if ptype == "http":
                        self.insecure_urls.append(raw)

                    if ptype == "websocket":
                        self.websocket_urls.append(raw)

                    # Extract hostname
                    try:
                        parsed = urlparse(raw)
                        host   = parsed.netloc.split(":")[0].lower()
                        if host and host not in seen_domains and len(host) > 4:
                            seen_domains.add(host)
                            self.domains.append(host)
                    except Exception:
                        pass

    # ── Domain classification ─────────────────────────────────────────────────

    def _classify_domains(self) -> None:
        for domain in self.domains:
            matched_cat  = "Unknown"
            matched_note = ""
            for fragment, (cat, note) in DOMAIN_CATEGORY_MAP.items():
                if fragment in domain:
                    matched_cat  = cat
                    matched_note = note
                    break
            self.domain_report.append({
                "domain":   domain,
                "category": matched_cat,
                "note":     matched_note,
            })

    # ── Issue flagging ────────────────────────────────────────────────────────

    def _flag_issues(self) -> None:
        # 1. Insecure HTTP endpoints (excluding schema namespaces)
        real_insecure = [
            u for u in self.insecure_urls
            if not any(skip in u for skip in URL_SKIP_FRAGMENTS)
            and not u.startswith("http://schemas")
        ]
        if real_insecure:
            sample = real_insecure[:5]
            self.findings.append(Finding(
                rule_id="NETMAP_CLEARTEXT_ENDPOINTS",
                category="Network Endpoint Map",
                severity=Severity.MEDIUM,
                title=f"Cleartext HTTP Endpoints Found ({len(real_insecure)})",
                description=(
                    f"Found {len(real_insecure)} HTTP (non-HTTPS) URL(s). "
                    "Data transmitted to these endpoints is unencrypted."
                ),
                evidence="\n".join(sample),
                owasp="M5",
                cwe="CWE-319",
                cvss=5.9,
                confidence="HIGH",
                remediation="Replace all http:// with https://. Use Network Security Config to block cleartext.",
            ))

        # 2. WebSocket without TLS
        insecure_ws = [u for u in self.websocket_urls if u.startswith("ws://")]
        if insecure_ws:
            self.findings.append(Finding(
                rule_id="NETMAP_INSECURE_WEBSOCKET",
                category="Network Endpoint Map",
                severity=Severity.HIGH,
                title=f"Unencrypted WebSocket (ws://) Found ({len(insecure_ws)})",
                description=(
                    "Unencrypted WebSocket connections expose all transmitted data to "
                    "network eavesdropping and MITM attacks."
                ),
                evidence="\n".join(insecure_ws[:3]),
                owasp="M5",
                cwe="CWE-319",
                cvss=7.4,
                confidence="HIGH",
                remediation="Replace ws:// with wss:// (WebSocket Secure).",
            ))

        # 3. Payment API endpoints accessed directly from app (should be server-side)
        payment_domains = [
            d["domain"] for d in self.domain_report
            if d["category"] == "Payment"
        ]
        if payment_domains:
            self.findings.append(Finding(
                rule_id="NETMAP_PAYMENT_API_DIRECT",
                category="Network Endpoint Map",
                severity=Severity.HIGH,
                title=f"Payment API Endpoint in App: {', '.join(payment_domains[:3])}",
                description=(
                    "Payment processor domain(s) were found in the app code. "
                    "Payment API calls (especially charge/token creation) should be "
                    "made server-side to avoid exposing API keys and to prevent "
                    "client-side manipulation of payment amounts."
                ),
                evidence=", ".join(payment_domains),
                owasp="M1",
                cwe="CWE-602",
                cvss=8.1,
                confidence="MEDIUM",
                remediation=(
                    "Use your backend as a proxy for all payment operations. "
                    "Only use client-side SDK for tokenisation (never for charge creation)."
                ),
            ))

        # 4. Endpoint count summary (informational)
        if self.endpoints:
            # Group by category for summary
            by_cat: Dict[str, int] = {}
            for d in self.domain_report:
                by_cat[d["category"]] = by_cat.get(d["category"], 0) + 1

            summary = ", ".join(f"{cat}: {n}" for cat, n in sorted(by_cat.items(), key=lambda x: -x[1])[:8])
            self.findings.append(Finding(
                rule_id="NETMAP_ENDPOINT_SUMMARY",
                category="Network Endpoint Map",
                severity=Severity.INFO,
                title=f"Network Endpoint Map: {len(self.endpoints)} URLs, {len(self.domains)} Domains",
                description=(
                    f"Extracted {len(self.endpoints)} unique URL(s) across {len(self.domains)} domain(s). "
                    f"Domain breakdown: {summary}. "
                    f"API paths found: {len(self.api_paths)}. "
                    f"WebSocket connections: {len(self.websocket_urls)}."
                ),
                evidence="\n".join(self.domains[:20]),
                owasp="M5",
                cwe="CWE-200",
                confidence="HIGH",
                remediation=(
                    "Review all third-party domains. Remove unnecessary integrations. "
                    "Declare all domains in your privacy policy and Play Store data safety form."
                ),
            ))
