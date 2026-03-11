"""
apkshield/analyzers/certificate.py
APK signing certificate analysis.
"""
from __future__ import annotations
import os
from typing import List

from apkshield import logger
from apkshield.models import Certificate, Finding, Severity

log = logger.get()

DEBUG_SUBJECT_HINTS = {"debug", "android", "test", "localhost", "unknown", "development"}


class CertificateAnalyzer:
    def __init__(self, extracted_dir: str):
        self.extracted_dir = extracted_dir
        self.findings: List[Finding] = []
        self.certs:    List[Certificate] = []

    def analyze(self) -> None:
        try:
            from OpenSSL import crypto
        except ImportError:
            log.warning("pyOpenSSL not available — skipping certificate analysis.")
            return

        cert_files = self._find_cert_files()
        for cf in cert_files:
            self._parse_cert(cf, crypto)

        log.info(f"Certificate analysis: {len(self.certs)} cert(s), {len(self.findings)} finding(s)")

    # ── File finder ───────────────────────────────────────────────────────────

    def _find_cert_files(self) -> List[str]:
        result = []
        for root, _, files in os.walk(self.extracted_dir):
            for fname in files:
                if fname.upper().endswith((".RSA", ".DSA", ".EC", ".PEM", ".CRT", ".CER")):
                    result.append(os.path.join(root, fname))
        return result

    # ── Parser ────────────────────────────────────────────────────────────────

    def _parse_cert(self, path: str, crypto) -> None:
        fname = os.path.basename(path)
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            return

        cert = None
        for loader in (crypto.FILETYPE_ASN1, crypto.FILETYPE_PEM):
            try:
                cert = crypto.load_certificate(loader, raw)
                break
            except Exception:
                continue

        if cert is None:
            return

        def _cn(x509_name) -> str:
            for key, val in x509_name.get_components():
                if key == b"CN":
                    return val.decode("utf-8", errors="replace")
            return "unknown"

        subject_cn = _cn(cert.get_subject())
        issuer_cn  = _cn(cert.get_issuer())
        alg        = cert.get_signature_algorithm().decode("utf-8", errors="replace")
        key_bits   = cert.get_pubkey().bits()
        not_after_raw  = cert.get_notAfter()
        not_before_raw = cert.get_notBefore()
        is_self_signed = subject_cn == issuer_cn
        is_expired     = cert.has_expired()

        c = Certificate(
            file=fname,
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            serial=str(cert.get_serial_number()),
            algorithm=alg,
            not_before=not_before_raw.decode() if not_before_raw else "",
            not_after=not_after_raw.decode()   if not_after_raw  else "",
            key_bits=key_bits,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
        )
        self.certs.append(c)

        # ── Findings ──────────────────────────────────────────────────────────

        # Debug / test certificate
        if any(h in subject_cn.lower() for h in DEBUG_SUBJECT_HINTS):
            self.findings.append(Finding(
                rule_id="CERT_DEBUG",
                category="Certificate",
                severity=Severity.HIGH,
                title="Debug / Test Certificate",
                description=(
                    f"The APK is signed with a certificate whose CN='{subject_cn}' "
                    f"suggests it is a debug or test key. Debug-signed APKs should never be distributed."
                ),
                evidence=f"Subject CN: {subject_cn} | Issuer: {issuer_cn}",
                file_path=fname,
                owasp="M7",
                cwe="CWE-295",
                cvss=6.5,
                remediation=(
                    "Generate a proper production keystore. Sign release builds with a "
                    "secure key stored in Android Studio's key management or a CI secrets vault."
                ),
            ))

        # Expired
        if is_expired:
            self.findings.append(Finding(
                rule_id="CERT_EXPIRED",
                category="Certificate",
                severity=Severity.HIGH,
                title="Signing Certificate is Expired",
                description=f"Certificate expired on {c.not_after}. Expired certificates may block installs on newer Android versions.",
                evidence=f"Not After: {c.not_after}",
                file_path=fname,
                owasp="M7",
                cwe="CWE-298",
                cvss=5.0,
                remediation="Renew the signing certificate and re-sign the APK.",
            ))

        # Weak algorithm
        alg_lower = alg.lower()
        if "md5" in alg_lower:
            self.findings.append(Finding(
                rule_id="CERT_MD5_ALGO",
                category="Certificate",
                severity=Severity.HIGH,
                title=f"Certificate Uses MD5 Signature: {alg}",
                description="MD5 signature algorithm is cryptographically broken and collision-prone.",
                evidence=f"Signature algorithm: {alg}",
                file_path=fname,
                owasp="M7",
                cwe="CWE-327",
                cvss=6.5,
                remediation="Re-sign with SHA-256 or SHA-512. Use RSA-4096 or EC P-384.",
            ))
        elif "sha1" in alg_lower:
            self.findings.append(Finding(
                rule_id="CERT_SHA1_ALGO",
                category="Certificate",
                severity=Severity.MEDIUM,
                title=f"Certificate Uses SHA-1 Signature: {alg}",
                description="SHA-1 is deprecated for signing purposes by NIST and most CAs.",
                evidence=f"Signature algorithm: {alg}",
                file_path=fname,
                owasp="M7",
                cwe="CWE-327",
                cvss=5.3,
                remediation="Re-sign with SHA-256 or SHA-512.",
            ))

        # Weak key size
        if key_bits < 2048:
            self.findings.append(Finding(
                rule_id="CERT_WEAK_KEY",
                category="Certificate",
                severity=Severity.HIGH,
                title=f"Weak Signing Key: {key_bits} bits",
                description=(
                    f"The signing key is only {key_bits} bits, below the 2048-bit RSA minimum. "
                    "This key can be factored with modern hardware."
                ),
                evidence=f"Key size: {key_bits} bits",
                file_path=fname,
                owasp="M7",
                cwe="CWE-326",
                cvss=7.0,
                remediation="Generate a new RSA-4096 or EC P-256/P-384 key pair for signing.",
            ))
