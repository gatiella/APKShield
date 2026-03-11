# 🛡️ APKShield v2.0 — Professional Android APK Security Scanner

A comprehensive static analysis tool for Android APK files. Detects security vulnerabilities, hardcoded secrets, weak cryptography, insecure network configurations, and validates OWASP Mobile Top 10 compliance — without executing any code.

---

## Features

| Category | What It Detects |
|---|---|
| **Manifest Analysis** | Dangerous permissions, debuggable flag, exported components, cleartext traffic, backup risks |
| **Secrets Detection** | AWS keys, Google API keys, Firebase URLs, Stripe keys, JWT tokens, private keys, GitHub tokens, Slack webhooks, Azure credentials, database connection strings |
| **Network Security** | HTTP URLs, cleartext traffic, TrustAll cert bypasses, SSL error ignoring, weak TLS versions, WebView misconfigs |
| **Cryptography** | DES/MD5/SHA1/RC4 usage, ECB mode, static IVs, hardcoded keys, weak PBKDF iterations |
| **Injection Risks** | SQL injection, command injection, path traversal, XSS in WebViews, log injection |
| **Data Storage** | World-readable files, sensitive log output, external storage misuse, SharedPreferences exposure |
| **Certificate Analysis** | Debug certs, self-signed certs, weak signature algorithms, small key sizes |
| **Native Libraries** | Secrets in .so files, unsafe C functions (gets, strcpy, system, exec) |
| **OWASP Compliance** | Full OWASP Mobile Top 10 (2024) coverage map |

---

## Installation

```bash
pip install -r requirements.txt
```

### requirements.txt
```
androguard>=4.0.0
reportlab>=4.0.0
pyOpenSSL>=24.0.0
```

---

## Usage

### Basic scan (HTML report)
```bash
python apkshield.py app.apk
```

### All report formats
```bash
python apkshield.py app.apk --format all --output ./reports
```

### JSON only, verbose
```bash
python apkshield.py app.apk -f json -v
```

### CI/CD mode (non-zero exit on HIGH/CRITICAL)
```bash
python apkshield.py app.apk --exit-code
```

### Filter by severity
```bash
python apkshield.py app.apk --severity-filter HIGH
```

### Filter by category
```bash
python apkshield.py app.apk --category-filter "Secrets"
```

### Save log to file
```bash
python apkshield.py app.apk --log scan.log -f all
```

---

## Command Line Options

```
positional arguments:
  apk                   Path to the APK file to scan

options:
  -h, --help            Show help message
  -f, --format FORMAT   Output format(s): json, html, pdf, all, or comma-separated
  -o, --output DIR      Output directory for reports (default: current directory)
  -v, --verbose         Enable verbose/debug logging
  --log FILE            Save log to file
  --no-banner           Suppress banner
  --severity-filter S   Only show findings: CRITICAL, HIGH, MEDIUM, LOW, INFO
  --category-filter C   Only show findings from matching category
  --exit-code           Exit with code 1 if HIGH or CRITICAL findings found
```

---

## Output Reports

### JSON Report
Machine-readable. Contains all findings, metadata, OWASP coverage, and remediation.
Ideal for integration with SIEM, ticketing systems, or custom pipelines.

### HTML Report
Dark-themed, fully styled. Includes:
- Risk score gauge
- Severity breakdown
- Findings grouped by category with code evidence
- OWASP Mobile Top 10 coverage table
- Permission analysis
- Certificate details

### PDF Report
Printable, professional format for client deliverables. Includes findings table,
OWASP coverage, and remediation guidance.

---

## Understanding the Risk Score

| Score | Label |
|---|---|
| 50–100 | CRITICAL RISK |
| 25–49 | HIGH RISK |
| 10–24 | MEDIUM RISK |
| 1–9 | LOW RISK |
| 0 | MINIMAL RISK |

Score formula: CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1 (capped at 100)

---

## OWASP Mobile Top 10 Coverage

- **M1** Improper Credential Usage
- **M2** Inadequate Supply Chain Security
- **M3** Insecure Authentication/Authorization
- **M4** Insufficient Input/Output Validation
- **M5** Insecure Communication
- **M6** Inadequate Privacy Controls
- **M7** Insufficient Binary Protections
- **M8** Security Misconfiguration
- **M9** Insecure Data Storage
- **M10** Insufficient Cryptography

---

## Architecture

```
apkshield/
├── apkshield.py      # CLI entry point
├── scanner.py        # Core engine: extractor, analyzers, pattern rules
├── reporter.py       # JSON, HTML, PDF report generators
└── README.md         # This file
```

### Scanning Pipeline

```
APK Input
    │
    ├─► Hash & Metadata (SHA256, MD5, file size)
    │
    ├─► APK Extraction (ZIP → extracted files)
    │
    ├─► AndroidManifest.xml Analysis
    │       ├─ Permissions (50+ dangerous permissions mapped)
    │       ├─ Debuggable / Backup / Cleartext flags
    │       └─ Exported components (activities, services, receivers)
    │
    ├─► Code Scanner (smali, java, xml, json, properties, config)
    │       ├─ Secrets (35+ patterns: AWS, Google, Stripe, JWT, ...)
    │       ├─ Network (cleartext, TrustAll, SSL bypass, WebView)
    │       ├─ Cryptography (DES, MD5, ECB, static IV, weak random)
    │       ├─ Injection (SQL, command, path traversal, XSS)
    │       └─ Storage (world-readable, log leaks, external storage)
    │
    ├─► Certificate Analysis (signature algo, key size, debug cert)
    │
    ├─► Native Library Analysis (.so binary string extraction)
    │
    └─► Report Generation (JSON + HTML + PDF)
```

---

## Legal Notice

This tool is for **authorized security assessments only**. You must have explicit permission to analyze any APK file. Unauthorized use may violate computer crime laws. The authors assume no liability for misuse.

---

## Extending APKShield

### Adding custom secret patterns

In `scanner.py`, add entries to `SECRET_PATTERNS`:
```python
("My Custom Key", r'MY_CUSTOM_KEY=[A-Za-z0-9]{32}', Severity.HIGH, "M10", "CWE-312"),
```

### Adding custom code checks

Add entries to any of the pattern lists:
`SECRET_PATTERNS`, `NETWORK_PATTERNS`, `CRYPTO_PATTERNS`, `INJECTION_PATTERNS`, `STORAGE_PATTERNS`

Each entry is a tuple: `(name, regex_pattern, Severity, owasp_id, cwe_id, remediation_text)`
