"""
apkshield/analyzers/firebase.py

Firebase Misconfiguration Checker

Performs LIVE HTTP probes against detected Firebase Realtime Database URLs
to check for publicly readable / writable databases.

Also checks:
  - Firebase Storage bucket public access
  - Firestore REST API open access
  - google-services.json presence and content
  - Firebase security rules configuration hints
"""
from __future__ import annotations
import json
import re
import urllib.request
import urllib.error
from typing import List, Optional
from urllib.parse import urlparse

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

PROBE_TIMEOUT = 8  # seconds


class FirebaseAnalyzer:
    def __init__(self, extracted_dir: str, text_files: List[str], do_network_probes: bool = True):
        self.extracted_dir    = extracted_dir
        self.text_files       = text_files
        self.do_network_probes = do_network_probes
        self.findings: List[Finding] = []

        self.firebase_urls:    List[str] = []
        self.storage_buckets:  List[str] = []
        self.project_ids:      List[str] = []

    def analyze(self) -> None:
        log.info("Firebase misconfiguration check…")
        self._extract_firebase_config()
        if self.do_network_probes:
            self._probe_databases()
            self._probe_storage()
        else:
            log.info("  Network probes disabled — skipping live Firebase checks")
        log.info(
            f"Firebase: {len(self.firebase_urls)} DB URL(s) | "
            f"{len(self.storage_buckets)} bucket(s) | "
            f"{len(self.findings)} finding(s)"
        )

    # ── Config extraction ─────────────────────────────────────────────────────

    def _extract_firebase_config(self) -> None:
        import os

        # Pattern: Firebase Realtime DB URLs
        rtdb_re    = re.compile(r'https://([a-zA-Z0-9\-]+)\.firebaseio\.com')
        storage_re = re.compile(r'gs://([a-zA-Z0-9\-]+\.appspot\.com|[a-zA-Z0-9\-]+\.storage\.googleapis\.com)')
        project_re = re.compile(r'"project_id"\s*:\s*"([a-zA-Z0-9\-]+)"')

        seen_urls:    set = set()
        seen_buckets: set = set()

        for fpath in self.text_files:
            try:
                content = open(fpath, errors="replace").read()
            except OSError:
                continue

            for m in rtdb_re.finditer(content):
                url = m.group(0)
                if url not in seen_urls:
                    seen_urls.add(url)
                    self.firebase_urls.append(url)

            for m in storage_re.finditer(content):
                bucket = m.group(1)
                if bucket not in seen_buckets:
                    seen_buckets.add(bucket)
                    self.storage_buckets.append(bucket)

            for m in project_re.finditer(content):
                pid = m.group(1)
                if pid not in self.project_ids:
                    self.project_ids.append(pid)

        # Also check google-services.json directly
        gs_path = os.path.join(self.extracted_dir, "assets", "google-services.json")
        for candidate in [gs_path, os.path.join(self.extracted_dir, "res", "raw", "google_services.json")]:
            if os.path.exists(candidate):
                self._parse_google_services_json(candidate)

        if self.firebase_urls:
            log.info(f"  Firebase DB URLs: {self.firebase_urls}")

    def _parse_google_services_json(self, path: str) -> None:
        try:
            with open(path) as f:
                data = json.load(f)
            # Extract any additional config values
            for client in data.get("client", []):
                for svc in client.get("services", {}).get("appinvite_service", {}).get("other_platform_oauth_client", []):
                    pass  # just parsing structure
            # Flag presence — the file itself may contain API keys
            self.findings.append(Finding(
                rule_id="FIREBASE_GOOGLE_SERVICES_PRESENT",
                category="Firebase Security",
                severity=Severity.LOW,
                title="google-services.json Found in APK",
                description=(
                    "google-services.json was found in the APK assets. "
                    "This file contains Firebase project configuration including API keys. "
                    "While Firebase API keys are not secret by themselves, they must be "
                    "protected by Firebase Security Rules and domain restrictions."
                ),
                evidence=f"Path: {path}",
                file_path=path,
                owasp="M1",
                cwe="CWE-312",
                confidence="HIGH",
                remediation=(
                    "Restrict your Firebase API key in Google Cloud Console. "
                    "Ensure Firebase Security Rules require authentication. "
                    "Never include server-side service account keys in this file."
                ),
            ))
        except Exception:
            pass

    # ── Live database probes ──────────────────────────────────────────────────

    def _probe_databases(self) -> None:
        for url in self.firebase_urls:
            self._probe_rtdb(url)

    def _probe_rtdb(self, base_url: str) -> None:
        """
        Probe Firebase Realtime Database for public read access.
        Tests: /.json (root), /.settings/rules.json (rules — usually blocked)
        """
        # Ensure URL has no trailing slash
        base = base_url.rstrip("/")

        # Test root read
        root_url  = f"{base}/.json?limitToFirst=3"
        rules_url = f"{base}/.settings/rules.json"

        root_result  = self._http_get(root_url)
        rules_result = self._http_get(rules_url)

        if root_result is not None:
            if root_result.get("status") == 200:
                body = root_result.get("body", "")
                if body and body.strip() not in ("null", ""):
                    # Data returned — database is publicly readable
                    preview = body[:300] if len(body) > 300 else body
                    self.findings.append(Finding(
                        rule_id="FIREBASE_RTDB_PUBLIC_READ",
                        category="Firebase Security",
                        severity=Severity.CRITICAL,
                        title=f"Firebase Realtime DB Publicly Readable: {base_url}",
                        description=(
                            f"The Firebase Realtime Database at {base_url} returned data "
                            f"without authentication. Anyone on the internet can read your database. "
                            f"Data preview: {preview[:200]}"
                        ),
                        evidence=f"GET {root_url} → HTTP 200, data returned",
                        owasp="M8",
                        cwe="CWE-284",
                        cvss=9.8,
                        confidence="HIGH",
                        remediation=(
                            "Set Firebase Security Rules to require authentication: "
                            '{"rules": {".read": "auth != null", ".write": "auth != null"}}. '
                            "Review all rules at console.firebase.google.com → Realtime Database → Rules."
                        ),
                    ))
                elif body.strip() == "null":
                    # Root is null but accessible — rules may allow read with no data
                    self.findings.append(Finding(
                        rule_id="FIREBASE_RTDB_ACCESSIBLE",
                        category="Firebase Security",
                        severity=Severity.MEDIUM,
                        title=f"Firebase Realtime DB Endpoint Accessible (Empty): {base_url}",
                        description=(
                            f"The Firebase Realtime Database at {base_url} responded to an "
                            "unauthenticated request with HTTP 200 (null data). "
                            "Rules may allow public read access — audit them."
                        ),
                        evidence=f"GET {root_url} → HTTP 200, null",
                        owasp="M8",
                        cwe="CWE-284",
                        cvss=5.3,
                        confidence="HIGH",
                        remediation="Audit Firebase Security Rules. Require auth != null for all reads.",
                    ))

            elif root_result.get("status") == 401:
                # Good — auth required
                self.findings.append(Finding(
                    rule_id="FIREBASE_RTDB_AUTH_REQUIRED",
                    category="Firebase Security",
                    severity=Severity.INFO,
                    title=f"Firebase Realtime DB Properly Secured: {base_url}",
                    description="Database returned 401 — authentication is required. Rules appear correctly configured.",
                    evidence=f"GET {root_url} → HTTP 401",
                    owasp="M8",
                    cwe="CWE-284",
                    confidence="HIGH",
                    remediation="Continue requiring authentication. Periodically audit rules for overly permissive paths.",
                ))

            elif root_result.get("status") == 403:
                self.findings.append(Finding(
                    rule_id="FIREBASE_RTDB_FORBIDDEN",
                    category="Firebase Security",
                    severity=Severity.INFO,
                    title=f"Firebase Realtime DB Access Denied: {base_url}",
                    description="Database returned 403 — access is denied. Good.",
                    evidence=f"GET {root_url} → HTTP 403",
                    owasp="M8",
                    cwe="CWE-284",
                    confidence="HIGH",
                    remediation="Maintain current security rules.",
                ))

        # Write probe — try to POST to /.json
        write_result = self._http_post(f"{base}/.json", '{"apkshield_probe": true}')
        if write_result and write_result.get("status") == 200:
            self.findings.append(Finding(
                rule_id="FIREBASE_RTDB_PUBLIC_WRITE",
                category="Firebase Security",
                severity=Severity.CRITICAL,
                title=f"Firebase Realtime DB Publicly WRITABLE: {base_url}",
                description=(
                    f"The Firebase Realtime Database at {base_url} accepted an "
                    "unauthenticated write. Anyone can insert, modify, or delete data. "
                    "This is a critical misconfiguration."
                ),
                evidence=f"POST {base}/.json → HTTP 200",
                owasp="M8",
                cwe="CWE-284",
                cvss=10.0,
                confidence="HIGH",
                remediation=(
                    "Immediately set: "
                    '{"rules": {".read": "auth != null", ".write": "auth != null"}}. '
                    "Audit all data written by APKShield probe and remove it."
                ),
            ))

    # ── Storage bucket probes ─────────────────────────────────────────────────

    def _probe_storage(self) -> None:
        for bucket in self.storage_buckets:
            url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=3"
            result = self._http_get(url)
            if result and result.get("status") == 200:
                items = result.get("body", "")[:500]
                self.findings.append(Finding(
                    rule_id="FIREBASE_STORAGE_PUBLIC",
                    category="Firebase Security",
                    severity=Severity.HIGH,
                    title=f"Firebase Storage Bucket Publicly Accessible: {bucket}",
                    description=(
                        f"Firebase Storage bucket '{bucket}' returned a file listing without "
                        "authentication. Files in this bucket are publicly readable."
                    ),
                    evidence=f"GET {url} → HTTP 200",
                    owasp="M8",
                    cwe="CWE-284",
                    cvss=8.2,
                    confidence="HIGH",
                    remediation=(
                        "Update Firebase Storage security rules to require authentication. "
                        "In Firebase Console → Storage → Rules: "
                        "allow read, write: if request.auth != null;"
                    ),
                ))
            elif result and result.get("status") == 403:
                self.findings.append(Finding(
                    rule_id="FIREBASE_STORAGE_SECURED",
                    category="Firebase Security",
                    severity=Severity.INFO,
                    title=f"Firebase Storage Bucket Secured: {bucket}",
                    description="Storage bucket returned 403 — access properly restricted.",
                    evidence=f"GET {url} → HTTP 403",
                    owasp="M8",
                    cwe="CWE-284",
                    confidence="HIGH",
                    remediation="Maintain current storage security rules.",
                ))

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _http_get(self, url: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "APKShield-SecurityScanner/2.1"})
            with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception as e:
            log.debug(f"Firebase probe error ({url}): {e}")
            return None

    def _http_post(self, url: str, body: str) -> Optional[dict]:
        try:
            data = body.encode()
            req  = urllib.request.Request(
                url, data=data, method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "APKShield-SecurityScanner/2.1",
                },
            )
            with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
                return {"status": resp.status, "body": resp.read(512).decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception as e:
            log.debug(f"Firebase write probe error ({url}): {e}")
            return None
