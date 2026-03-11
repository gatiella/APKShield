"""
apkshield/rules/owasp.py
OWASP Mobile Top 10 (2024) definitions.
"""

OWASP_MOBILE_TOP10 = {
    "M1":  "Improper Credential Usage",
    "M2":  "Inadequate Supply Chain Security",
    "M3":  "Insecure Authentication / Authorization",
    "M4":  "Insufficient Input / Output Validation",
    "M5":  "Insecure Communication",
    "M6":  "Inadequate Privacy Controls",
    "M7":  "Insufficient Binary Protections",
    "M8":  "Security Misconfiguration",
    "M9":  "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

OWASP_DESCRIPTIONS = {
    "M1":  "Hardcoded credentials, insecure secret storage, improper key management.",
    "M2":  "Vulnerable third-party libraries, tampered components, unsigned builds.",
    "M3":  "Broken authentication, missing authorisation checks, session mismanagement.",
    "M4":  "SQL injection, command injection, XSS, insufficient input sanitisation.",
    "M5":  "Cleartext traffic, broken TLS, missing certificate pinning.",
    "M6":  "Excessive data collection, insecure data sharing, privacy policy violations.",
    "M7":  "No obfuscation, anti-debug absent, root/emulator detection missing.",
    "M8":  "Insecure defaults, unnecessary permissions, debuggable production builds.",
    "M9":  "Sensitive data in logs/shared prefs/external storage, unencrypted databases.",
    "M10": "Weak algorithms, hardcoded keys, poor random number generation.",
}
