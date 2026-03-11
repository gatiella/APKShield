# 🛡️ APKShield v2.2
### Professional Android APK Security Scanner

APKShield is a comprehensive **static and dynamic-resistance analysis** tool for Android APK files. It detects security vulnerabilities, hardcoded secrets, weak cryptography, insecure network configurations, performs live Firebase misconfiguration probes, maps every API endpoint the app communicates with, audits ad SDK data collection practices, and analyses in-app purchase validation quality — all mapped to the **OWASP Mobile Top 10** without executing any app code.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan → HTML report
python -m apkshield app.apk

# All formats
python -m apkshield app.apk -f all -o ./reports

# Skip live network probes (faster, offline-safe)
python -m apkshield app.apk -f all --no-network-probes

# CI mode: exit code 1 if HIGH/CRITICAL found
python -m apkshield app.apk -f sarif --exit-code
```

---

## Installation

**Requirements:** Python 3.9+

```bash
pip install -r requirements.txt
```

```
androguard>=4.0.0    # APK parsing and binary manifest decoding
reportlab>=4.0.0     # PDF generation
pyOpenSSL>=24.0.0    # Certificate analysis
```

Or install as a package (enables the `apkshield` command globally):

```bash
pip install -e .
apkshield app.apk -f all
```

---

## Usage

```
python -m apkshield <apk> [options]

Arguments:
  apk                     Path to the APK file to scan

Options:
  -f, --format FORMAT     Output format(s):
                            json    Machine-readable JSON
                            html    Dark-themed interactive report
                            pdf     Printable professional report
                            sarif   SARIF 2.1.0 for GitHub/GitLab CI
                            all     All four formats
                            Comma-separated: e.g. json,html,sarif
                          Default: html

  -o, --output DIR        Output directory (default: current directory)
  -v, --verbose           Debug-level logging
  --log FILE              Save log output to a file
  --no-banner             Suppress the ASCII banner
  --severity-filter SEV   Only include findings at or above this severity:
                            CRITICAL | HIGH | MEDIUM | LOW | INFO
  --category-filter STR   Only include findings whose category contains STR
  --exit-code             Exit with code 1 if HIGH or CRITICAL findings exist
                          (useful for blocking CI pipelines)
  --no-network-probes     Skip live HTTP probes (Firebase DB, Storage buckets).
                          Use this for air-gapped environments or faster scans.
```

### Examples

```bash
# Scan and open the HTML report
python -m apkshield suspicious.apk -o ./reports
open ./reports/suspicious_*.html

# SARIF output for GitHub Code Scanning
python -m apkshield app.apk -f sarif -o .

# Only critical and high findings
python -m apkshield app.apk --severity-filter HIGH

# Only network-related findings
python -m apkshield app.apk --category-filter "Network"

# CI pipeline gate — skip live probes for speed
python -m apkshield release.apk -f json,sarif --exit-code --no-network-probes
echo "Exit code: $?"   # 1 = HIGH/CRITICAL found, 0 = clean

# Full scan including live Firebase probes
python -m apkshield app.apk -f all -o ./reports
```

---

## What It Detects

### 🔑 Secrets & Credentials (35+ patterns)

| Pattern | Severity |
|---|---|
| AWS Access Key ID (AKIA…) | CRITICAL |
| AWS Secret Access Key | CRITICAL |
| Stripe Live Secret Key (sk_live_…) | CRITICAL |
| GitHub Personal Access Token (ghp_…) | CRITICAL |
| RSA / EC / SSH Private Keys | CRITICAL |
| Database password fields | CRITICAL |
| Azure Storage connection strings | CRITICAL |
| Google OAuth Access Token | CRITICAL |
| Google API Key (AIza…) | HIGH |
| GitLab PAT (glpat-…) | HIGH |
| Slack Bot/User tokens (xoxb-…) | HIGH |
| SendGrid API Key (SG.…) | HIGH |
| JWT Tokens | HIGH |
| Hardcoded passwords / secrets / tokens | HIGH |
| Stripe Publishable Key | HIGH |
| Azure SAS tokens | HIGH |
| Firebase Realtime DB URLs | MEDIUM |
| Stripe Test Keys | MEDIUM |
| Internal IPv4 addresses | LOW |

### 📋 Manifest Analysis

| Check | Severity |
|---|---|
| `android:debuggable="true"` | HIGH |
| `android:allowBackup="true"` | MEDIUM |
| `android:usesCleartextTraffic="true"` | HIGH |
| Exported components without permission protection | HIGH/MEDIUM |
| Missing Network Security Configuration | MEDIUM |
| Empty `taskAffinity` (task hijacking) | HIGH |
| `minSdkVersion` below 21 | MEDIUM |
| Custom permissions with `normal` protection level | MEDIUM |
| Exported `FileProvider` | HIGH |
| 50+ dangerous permissions classified by risk | CRITICAL–INFO |

### 🌐 Network Security

| Check | Severity |
|---|---|
| TrustAll X509TrustManager | CRITICAL |
| Empty `checkServerTrusted` / `getAcceptedIssuers` | CRITICAL |
| SSL errors ignored in WebView (`proceed()`) | CRITICAL |
| `setAllowUniversalAccessFromFileURLs(true)` | CRITICAL |
| `HostnameVerifier` accepting all hosts | CRITICAL |
| Cleartext HTTP URLs (with false-positive whitelist) | MEDIUM |
| Weak TLS versions (SSLv3, TLS 1.0/1.1) | HIGH |
| `setAllowFileAccess(true)` in WebView | HIGH |
| `setJavaScriptEnabled(true)` | MEDIUM |
| `addJavascriptInterface` usage | MEDIUM |

### 🔐 Cryptography

| Check | Severity |
|---|---|
| Hardcoded `SecretKeySpec` key | CRITICAL |
| DES / 3DES cipher | HIGH |
| ECB mode | HIGH |
| RC4 cipher | HIGH |
| MD5 hashing | HIGH |
| Static / zero IV (`IvParameterSpec(new byte[])`) | HIGH |
| `Math.random()` / `new Random()` for security | MEDIUM |
| SHA-1 hashing | MEDIUM |
| BKS KeyStore instead of AndroidKeyStore | MEDIUM |
| Low PBKDF2 iteration count | MEDIUM |

### 💉 Injection

| Check | Severity |
|---|---|
| SQL injection via string concatenation in `rawQuery` | HIGH |
| Command injection via `Runtime.exec` / `ProcessBuilder` | HIGH |
| XSS via `WebView.loadUrl/loadData` with concatenation | HIGH |
| Dynamic class loading (`DexClassLoader`) | HIGH |
| Path traversal in file operations | MEDIUM |
| Intent extras forwarded without validation | MEDIUM |
| `addJavascriptInterface` injection surface | MEDIUM |
| Log injection | LOW |

### 💾 Insecure Data Storage

| Check | Severity |
|---|---|
| Sensitive values in log output | HIGH |
| `System.out.println` with passwords/tokens | HIGH |
| `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` | HIGH |
| `getExternalStorageDirectory()` for sensitive data | MEDIUM |
| `android:allowBackup="true"` | MEDIUM |
| Unencrypted `SharedPreferences` with sensitive data | LOW |
| Unencrypted SQLite database | LOW |

### 🔒 Binary Protections

| Check | Severity |
|---|---|
| Code unobfuscated (no ProGuard/R8) | MEDIUM |
| `DexClassLoader` / dynamic code loading | HIGH |
| Reflection with dynamic class names | MEDIUM |
| Mutable `PendingIntent` (hijacking risk) | MEDIUM |
| Root detection absent | MEDIUM |
| Anti-debug checks absent | LOW |

### 📜 Certificate Analysis

| Check | Severity |
|---|---|
| Debug / test signing certificate | HIGH |
| Expired certificate | HIGH |
| MD5 signature algorithm | HIGH |
| RSA key < 2048 bits | HIGH |
| SHA-1 signature algorithm | MEDIUM |
| Self-signed certificate | INFO |

### ⚙️ Native Library Analysis

| Check | Severity |
|---|---|
| `gets()` — exploitable buffer overflow | CRITICAL |
| `strcpy()` / `strcat()` — buffer overflow risk | HIGH |
| `system()` / `exec()` / `popen()` — command injection | HIGH |
| `sprintf()` / `vsprintf()` — format string risk | MEDIUM |
| Secrets found in `.so` binary strings | CRITICAL–HIGH |

### 🧬 DEX Bytecode Analysis *(new in v2.2)*

Performs actual bytecode-level analysis using androguard's call graph, falling back to smali opcode parsing if the full analysis object is unavailable.

| Check | Severity |
|---|---|
| Taint flow: user input → SQL rawQuery (SQL injection) | HIGH |
| Taint flow: user input → Runtime.exec (command injection) | CRITICAL |
| Taint flow: user input → WebView.loadUrl (XSS/redirect) | HIGH |
| Taint flow: user input → FileOutputStream (path traversal) | MEDIUM |
| Taint flow: user input → Log.d/v (data leakage) | MEDIUM |
| Weak cipher confirmed by bytecode (`Cipher.getInstance("DES")`) | HIGH |
| Dangerous API call: `Runtime.exec()` | HIGH |
| Dangerous API call: `DexClassLoader` (dynamic DEX loading) | HIGH |
| Dangerous API call: `TelephonyManager.getSubscriberId()` (IMSI) | HIGH |
| Dangerous API call: `TelephonyManager.getDeviceId()` (IMEI) | MEDIUM |
| Play Integrity / SafetyNet attestation present | INFO |
| Debugger detection present | INFO |

Taint sources tracked: `EditText.getText`, `Intent.getStringExtra`, `Uri.getQueryParameter`, `Cursor.getString`, `SharedPreferences.getString`, and more. Tracks up to 4 call hops from source to sink.

### 🛡️ Dynamic Analysis Resistance *(new in v2.2)*

| Check | Severity |
|---|---|
| Certificate pinning not detected (no CertificatePinner/TrustKit) | HIGH |
| No Frida instrumentation detection | MEDIUM |
| No root detection | MEDIUM |
| No anti-debug checks | LOW |
| OkHttp client missing CertificatePinner | HIGH |
| Null TrustManager / HostnameVerifier bypass | CRITICAL |
| Frida gadget signatures in native library | CRITICAL |
| Xposed module signatures in native library | HIGH |
| SSL unpinning bypass patterns | HIGH |

### 📦 Ad SDK & Privacy Audit *(new in v2.2)*

Identifies ad networks and maps their data collection, required permissions, and GDPR consent API. 11 ad SDKs in the database including severity ratings.

| SDK | Privacy Risk |
|---|---|
| StartApp | CRITICAL — history of excessive location/device harvesting |
| Meta Audience Network | HIGH — cross-app tracking across Meta ecosystem |
| IronSource (mediation) | HIGH — multiplies data exposure across networks |
| Google Mobile Ads (AdMob) | MEDIUM |
| Unity Ads, AppLovin, Chartboost, Vungle | MEDIUM |
| MoPub | HIGH — deprecated March 2023, no security patches |
| InMobi, PubNative/Verve | MEDIUM |

Also detects: absent consent framework (GDPR/CCPA), background location granted alongside ad SDKs (CRITICAL).

### 💳 In-App Purchase Security *(new in v2.2)*

| Check | Severity |
|---|---|
| IAP present but no server-side validation signals | CRITICAL |
| Purchase state comparison in client code | HIGH |
| Premium status stored in SharedPreferences | HIGH |
| Local signature verification (bypassable) | HIGH |
| No runtime signature check with IAP present | HIGH |
| No root detection with IAP present | HIGH |
| No Play Integrity with IAP present | MEDIUM |
| Anti-tampering protections summary | INFO |

Detects: Google Play Billing, Amazon IAP, Samsung IAP, Huawei IAP, RevenueCat, android-inapp-billing-v3.

### 🔥 Firebase Misconfiguration *(new in v2.2)*

Performs **live HTTP probes** against every Firebase Realtime Database URL found in the APK.

| Check | Severity |
|---|---|
| RTDB returns data without authentication (`/.json` → 200 + data) | CRITICAL |
| RTDB accepts unauthenticated write (`POST /.json` → 200) | CRITICAL |
| RTDB accessible but empty (rules may be open) | MEDIUM |
| RTDB properly secured (401/403) | INFO |
| Firebase Storage bucket publicly readable | HIGH |
| Firebase Storage bucket secured | INFO |
| `google-services.json` found in APK assets | LOW |

Use `--no-network-probes` to skip live probes in CI or air-gapped environments.

### 🗺️ Network Endpoint Map *(new in v2.2)*

Extracts and classifies every URL and domain the app communicates with.

| Check | Severity |
|---|---|
| Cleartext HTTP endpoints found | MEDIUM |
| Unencrypted WebSocket (`ws://`) | HIGH |
| Payment API domain accessed directly from app | HIGH |
| Full endpoint map (counts by category) | INFO |

Domain categories detected: Advertising · Analytics · Attribution · Payment · Auth · CDN · Cloud/Infra · Firebase · Monitoring · Push · Maps · Support/CRM. 50+ known domains in the classification database.

### 📦 Third-Party SDK Detection

APKShield fingerprints **32 known SDKs** including ad networks, analytics, crash reporting, IAP libraries, and payment SDKs:

Analytics: Firebase · Amplitude · Mixpanel · Segment · Crashlytics · Sentry · Bugsnag · App Center · HockeyApp

Ad Networks: Google Mobile Ads · Meta Audience Network · Unity Ads · IronSource · AppLovin · Chartboost · Vungle · MoPub (deprecated) · StartApp · InMobi · PubNative

Attribution: AppsFlyer · Adjust · Branch.io

IAP: Google Play Billing · Amazon IAP · RevenueCat

Payments: Stripe Android SDK · PayPal

Other: OneSignal · Braze

---

## Report Formats

### HTML
Dark-themed, single-file, fully self-contained. Opens in any browser with no server required. Includes:
- Executive summary with top issues and risk flags
- Risk score (0–100, nonlinear scale)
- Severity breakdown with visual bars
- All findings grouped by category, each with evidence snippet, file location, CVSS score, confidence level, OWASP/CWE tags, and remediation guidance
- OWASP Mobile Top 10 coverage table with descriptions
- Permission analysis with per-permission severity and remediation
- Third-party SDK list
- Certificate details
- Native library list

### JSON
Machine-readable. Suitable for SIEM ingestion, ticket creation, dashboards, or custom pipelines. Contains the full result object including all findings, metadata, OWASP coverage map, component lists, and certificate details.

### PDF
Printable, professional format for client deliverables and audit reports. Generated with ReportLab; falls back to a plain `.txt` file if ReportLab is unavailable.

### SARIF
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) format for native integration with GitHub Code Scanning, GitLab SAST, VS Code, and other SARIF-compatible tools. Each finding includes rule metadata, location, severity, confidence, and remediation text.

**GitHub Actions example:**
```yaml
- name: Scan APK
  run: python -m apkshield app.apk -f sarif -o .

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: app_*.sarif
```

---

## Risk Score

The risk score (0–100) uses a nonlinear formula to prevent score inflation from many low-severity findings:

```
raw   = CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1
score = (raw / (raw + 20)) × 100   [capped at 100]
```

| Score | Label |
|---|---|
| 75–100 | CRITICAL RISK |
| 50–74  | HIGH RISK |
| 25–49  | MEDIUM RISK |
| 5–24   | LOW RISK |
| 0–4    | MINIMAL RISK |

---

## OWASP Mobile Top 10 (2024)

Every finding is tagged with the relevant OWASP Mobile Top 10 category:

| ID | Category |
|---|---|
| M1 | Improper Credential Usage |
| M2 | Inadequate Supply Chain Security |
| M3 | Insecure Authentication / Authorization |
| M4 | Insufficient Input / Output Validation |
| M5 | Insecure Communication |
| M6 | Inadequate Privacy Controls |
| M7 | Insufficient Binary Protections |
| M8 | Security Misconfiguration |
| M9 | Insecure Data Storage |
| M10 | Insufficient Cryptography |

---

## Project Structure

```
apkshield/
│
├── apkshield/                    # Main Python package
│   ├── __init__.py               # Version, package metadata
│   ├── __main__.py               # CLI entry point (python -m apkshield)
│   ├── models.py                 # Finding, ScanResult, Certificate dataclasses
│   ├── logger.py                 # Centralised logging
│   ├── scanner.py                # Orchestrator — runs all analyzers in sequence
│   │
│   ├── analyzers/                # One module per analysis domain
│   │   ├── extractor.py          # Safe ZIP extraction + SHA-256/SHA-1/MD5
│   │   ├── manifest.py           # AndroidManifest.xml parser and checker
│   │   ├── code.py               # Regex scanner for smali/Java/XML/JSON/props
│   │   ├── certificate.py        # Signing certificate analysis
│   │   ├── native.py             # .so binary string extraction + obfuscation check
│   │   ├── dex.py                # DEX bytecode call graph + taint analysis  ← v2.2
│   │   ├── dynamic.py            # Frida/Xposed/SSL-unpinning resistance      ← v2.2
│   │   ├── ads.py                # Ad SDK detection + privacy audit            ← v2.2
│   │   ├── integrity.py          # IAP validation quality + anti-tampering     ← v2.2
│   │   ├── firebase.py           # Live Firebase misconfiguration probes       ← v2.2
│   │   └── network_map.py        # API endpoint extraction + domain classifier ← v2.2
│   │
│   ├── rules/                    # Detection logic separated from analyzer code
│   │   ├── owasp.py              # OWASP Mobile Top 10 definitions + descriptions
│   │   ├── permissions.py        # 50+ Android permission risk database
│   │   └── patterns.py           # All regex rule sets + URL whitelist + SDK fingerprints (32)
│   │
│   └── reports/                  # One module per output format
│       ├── json_report.py
│       ├── html_report.py
│       ├── pdf_report.py
│       └── sarif_report.py
│
├── setup.py                      # pip install support
└── requirements.txt
```

### Scan Pipeline

```
APK file
  │
  ├─▶ compute_hashes()           SHA-256 · SHA-1 · MD5
  ├─▶ APKExtractor.extract()     Safe ZIP extraction (path traversal protected)
  ├─▶ androguard APK()           Binary manifest decoding (best-effort)
  │
  ├─▶ ManifestAnalyzer
  │     ├─ Dangerous permissions (50+)
  │     ├─ Debuggable / backup / cleartext flags
  │     ├─ Exported components without permission guards
  │     ├─ Task hijacking, custom permissions, FileProvider
  │     └─ minSdkVersion, Network Security Config presence
  │
  ├─▶ CodeScanner                (smali · Java · XML · JSON · .properties · …)
  │     ├─ Secrets (35+ patterns)
  │     ├─ Network security
  │     ├─ Cryptography
  │     ├─ Injection risks
  │     ├─ Insecure storage
  │     ├─ Binary protections
  │     └─ Third-party SDK fingerprinting (32 SDKs)
  │
  ├─▶ CertificateAnalyzer        .RSA · .DSA · .PEM · .CRT
  │     ├─ Debug / test certificates
  │     ├─ Expired certificates
  │     ├─ Weak signature algorithms (MD5, SHA-1)
  │     └─ Small key sizes (< 2048 bits)
  │
  ├─▶ NativeAnalyzer             .so libraries
  │     ├─ Secrets in binary strings
  │     ├─ Unsafe C functions (gets, strcpy, system, exec …)
  │     └─ Obfuscation heuristic (smali class name entropy)
  │
  ├─▶ DexAnalyzer                DEX bytecode                         ← v2.2
  │     ├─ Call graph construction (via androguard, or smali fallback)
  │     ├─ Taint tracking: user input → dangerous sinks (up to 4 hops)
  │     ├─ Dangerous API call detection (14 APIs)
  │     └─ Weak cipher confirmation from bytecode constants
  │
  ├─▶ DynamicAnalyzer            Instrumentation resistance           ← v2.2
  │     ├─ Certificate pinning presence
  │     ├─ Frida / Xposed gadget signatures in native libs
  │     ├─ SSL unpinning bypass patterns
  │     └─ Missing: pinning / Frida detection / root detection / anti-debug
  │
  ├─▶ AdsAnalyzer                Ad SDK privacy audit                 ← v2.2
  │     ├─ 11 ad SDK database (data collected, permissions, consent API)
  │     ├─ GDPR/CCPA consent framework detection
  │     └─ Background location + ad SDK (CRITICAL combo)
  │
  ├─▶ IntegrityAnalyzer          IAP + anti-tampering                 ← v2.2
  │     ├─ IAP library detection (6 libraries)
  │     ├─ Client-side vs server-side purchase validation
  │     └─ Anti-tamper: signature check, root, emulator, debugger, Play Integrity
  │
  ├─▶ FirebaseAnalyzer           Live misconfiguration probes         ← v2.2
  │     ├─ Extract all firebaseio.com URLs from APK
  │     ├─ GET /.json → public read check
  │     ├─ POST /.json → public write check
  │     └─ Storage bucket public listing check
  │        (skipped with --no-network-probes)
  │
  ├─▶ NetworkMapper              Endpoint extraction + classification ← v2.2
  │     ├─ All HTTPS/HTTP/WebSocket URLs
  │     ├─ API path extraction (/api/v1/…)
  │     ├─ Domain classification (50+ known domains, 13 categories)
  │     └─ Flags: cleartext endpoints, insecure WebSocket, payment API direct access
  │
  └─▶ Report generation          JSON · HTML · PDF · SARIF
```

---

## Extending APKShield

### Add a custom secret pattern

Open `apkshield/rules/patterns.py` and add an entry to `SECRET_PATTERNS`:

```python
(
    "My Internal Token",                      # Display name
    r'INT-[A-Za-z0-9]{32}',                  # Regex pattern
    Severity.HIGH,                            # Severity
    "M1",                                     # OWASP category
    "CWE-798",                                # CWE ID
    "Rotate the token and move it server-side.",  # Remediation
    "HIGH",                                   # Confidence: HIGH | MEDIUM | LOW
),
```

### Add a custom network check

Add to `NETWORK_PATTERNS` in the same file — same tuple format.

### Add an ad SDK to the privacy database

Open `apkshield/analyzers/ads.py` and add an entry to `AD_SDK_DATABASE`:

```python
"com.mynetwork.sdk": {
    "name": "MyNetwork Ads",
    "category": "Ad Network",
    "data_collected": ["Advertising ID", "Device info"],
    "privacy_risk": Severity.MEDIUM,
    "required_permissions": ["INTERNET"],
    "optional_permissions": ["ACCESS_FINE_LOCATION"],
    "notes": "Consent required under GDPR.",
    "consent_api": "MyNetwork Consent SDK",
},
```

### Add a domain to the network map classifier

Open `apkshield/analyzers/network_map.py` and add to `DOMAIN_CATEGORIES`:

```python
("api.myservice.com", "Payment", "MyService payment API"),
```

### Add a taint sink to DEX analysis

Open `apkshield/analyzers/dex.py` and add to `TAINT_SINKS`:

```python
("Lcom/myapp/DataStore;", "write",
 "Sensitive data written to custom store", Severity.MEDIUM, "M9", "CWE-312"),
```

### Add a false-positive URL exemption

Add the domain to `HTTP_WHITELIST` at the top of `patterns.py`:

```python
HTTP_WHITELIST = {
    "schemas.android.com",
    "your-internal-schema-domain.example",   # ← add here
    ...
}
```

### Add a new permission

Add to `DANGEROUS_PERMISSIONS` in `apkshield/rules/permissions.py`:

```python
"com.example.permission.CUSTOM": (
    Severity.HIGH,
    "Description of what this permission allows.",
    "Remediation advice for this permission.",
),
```

---

## False Positive Controls

APKShield applies several filters to reduce noise:

- **HTTP URL whitelist** — XML namespaces (`schemas.android.com`, `www.w3.org`, etc.) are never flagged as cleartext HTTP
- **Placeholder suppression** — values containing `example`, `placeholder`, `yourkey`, `changeme`, `test123`, `dummy`, etc. are skipped
- **Per-file deduplication** — the same rule triggered on the same line of the same file produces exactly one finding
- **Confidence field** — rules are rated HIGH / MEDIUM / LOW confidence; use `--severity-filter` or post-process the JSON to tune your threshold

---

## Legal Notice

APKShield is for **authorised security assessments only**. You must have explicit written permission to analyse any APK file you do not own. Unauthorised analysis may violate computer crime laws in your jurisdiction. The authors accept no liability for misuse.