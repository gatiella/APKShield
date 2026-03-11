"""
apkshield/analyzers/dex.py

DEX Bytecode Analyzer
Uses androguard's full analysis API to:
  - Build a method call graph
  - Track tainted data from dangerous sources → dangerous sinks
  - Detect reflection / dynamic loading chains
  - Find crypto misuse via actual API call detection (not just regex)

Falls back gracefully if androguard is not available.
"""
from __future__ import annotations
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from apkshield import logger
from apkshield.models import Finding, Severity

log = logger.get()

# ── Taint sources: methods whose return values are user-controlled ────────────
TAINT_SOURCES: List[Tuple[str, str]] = [
    # (class_pattern, method_pattern)
    ("Landroid/widget/EditText;",          "getText"),
    ("Landroid/widget/TextView;",          "getText"),
    ("Landroid/content/Intent;",           "getStringExtra"),
    ("Landroid/content/Intent;",           "getBundleExtra"),
    ("Landroid/content/Intent;",           "getData"),
    ("Landroid/net/Uri;",                  "getQueryParameter"),
    ("Landroid/net/Uri;",                  "getPath"),
    ("Landroid/content/SharedPreferences;","getString"),
    ("Landroid/database/Cursor;",          "getString"),
    ("Landroid/database/Cursor;",          "getBlob"),
    ("Ljava/io/InputStream;",              "read"),
    ("Landroid/content/ContentResolver;",  "query"),
    ("Ljava/net/URL;",                     "openConnection"),
    ("Lokhttp3/Request;",                  "body"),
]

# ── Taint sinks: methods that execute tainted data dangerously ────────────────
TAINT_SINKS: List[Tuple[str, str, str, Severity, str, str]] = [
    # (class_pattern, method_pattern, vuln_type, severity, owasp, cwe)
    ("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery",
     "SQL Injection", Severity.HIGH, "M4", "CWE-89"),
    ("Landroid/database/sqlite/SQLiteDatabase;", "execSQL",
     "SQL Injection", Severity.HIGH, "M4", "CWE-89"),
    ("Ljava/lang/Runtime;",                       "exec",
     "Command Injection", Severity.CRITICAL, "M4", "CWE-78"),
    ("Ljava/lang/ProcessBuilder;",                "<init>",
     "Command Injection", Severity.CRITICAL, "M4", "CWE-78"),
    ("Landroid/webkit/WebView;",                  "loadUrl",
     "XSS / Open Redirect", Severity.HIGH, "M4", "CWE-79"),
    ("Landroid/webkit/WebView;",                  "loadData",
     "XSS", Severity.HIGH, "M4", "CWE-79"),
    ("Ljava/io/FileOutputStream;",                "<init>",
     "Path Traversal", Severity.MEDIUM, "M4", "CWE-22"),
    ("Ljava/io/File;",                            "<init>",
     "Path Traversal", Severity.MEDIUM, "M4", "CWE-22"),
    ("Landroid/util/Log;",                        "d",
     "Sensitive Data in Log", Severity.MEDIUM, "M9", "CWE-532"),
    ("Landroid/util/Log;",                        "v",
     "Sensitive Data in Log", Severity.MEDIUM, "M9", "CWE-532"),
    ("Ljavax/crypto/Cipher;",                     "getInstance",
     "Crypto Misuse (tainted algorithm)", Severity.HIGH, "M10", "CWE-327"),
    ("Ljava/net/URL;",                            "<init>",
     "SSRF / Tainted URL", Severity.MEDIUM, "M5", "CWE-918"),
]

# ── Dangerous standalone API calls (no taint needed — just presence) ──────────
DANGEROUS_APIS: List[Tuple[str, str, str, Severity, str, str, str]] = [
    # (class, method, description, severity, owasp, cwe, remediation)
    ("Ljava/lang/Runtime;", "exec",
     "Shell command execution via Runtime.exec()",
     Severity.HIGH, "M4", "CWE-78",
     "Avoid shell execution. If required, whitelist all inputs strictly."),

    ("Ldalvik/system/DexClassLoader;", "<init>",
     "Dynamic DEX loading — can load arbitrary code at runtime",
     Severity.HIGH, "M7", "CWE-470",
     "Verify DEX integrity before loading. Avoid loading from external storage."),

    ("Ldalvik/system/PathClassLoader;", "<init>",
     "Dynamic class loading via PathClassLoader",
     Severity.MEDIUM, "M7", "CWE-470",
     "Audit all dynamic class loading. Ensure source is trusted."),

    ("Ljava/lang/reflect/Method;", "invoke",
     "Reflective method invocation — can bypass access controls",
     Severity.MEDIUM, "M7", "CWE-470",
     "Validate class/method names against a whitelist before reflective calls."),

    ("Landroid/app/ActivityManager;", "getRunningAppProcesses",
     "Enumerates running processes — used for detection evasion checks",
     Severity.LOW, "M7", "CWE-200",
     "Acceptable for process monitoring apps. Audit usage context."),

    ("Landroid/telephony/TelephonyManager;", "getDeviceId",
     "Reads IMEI/MEID — legacy device identifier, deprecated API 29+",
     Severity.MEDIUM, "M6", "CWE-359",
     "Use Android Advertising ID or app-generated UUID instead of IMEI."),

    ("Landroid/telephony/TelephonyManager;", "getSubscriberId",
     "Reads IMSI — unique network subscriber identifier",
     Severity.HIGH, "M6", "CWE-359",
     "Remove. IMSI collection is a serious privacy violation."),

    ("Landroid/provider/Settings$Secure;", "ANDROID_ID",
     "Reads Android ID — persistent device identifier",
     Severity.LOW, "M6", "CWE-359",
     "Acceptable for fraud prevention. Disclose in privacy policy."),

    ("Ljavax/crypto/Cipher;", "getInstance",
     "Cipher.getInstance() call — verify algorithm is not weak",
     Severity.INFO, "M10", "CWE-327",
     "Ensure AES/GCM/NoPadding is used. Never use ECB or DES."),

    ("Ljava/security/MessageDigest;", "getInstance",
     "MessageDigest.getInstance() — verify not MD5 or SHA-1",
     Severity.INFO, "M10", "CWE-327",
     "Use SHA-256 or SHA-3. Never use MD5 or SHA-1 for security."),

    ("Landroid/content/pm/PackageManager;", "getInstallerPackageName",
     "Checks how app was installed — often used for piracy detection",
     Severity.INFO, "M7", "CWE-693",
     "Informational. Ensure the check is not the only protection layer."),

    ("Landroid/os/Debug;", "isDebuggerConnected",
     "Checks for attached debugger — anti-debug protection present",
     Severity.INFO, "M7", "CWE-693",
     "Good practice. Ensure check is in security-critical paths."),

    ("Lcom/google/android/gms/safetynet/SafetyNetApi;", "attest",
     "SafetyNet attestation — device integrity check (deprecated, use Play Integrity)",
     Severity.INFO, "M7", "CWE-693",
     "Migrate to Play Integrity API. SafetyNet is deprecated as of 2024."),

    ("Lcom/google/android/play/core/integrity/IntegrityManager;", "requestIntegrityToken",
     "Play Integrity API — device and app integrity check",
     Severity.INFO, "M7", "CWE-693",
     "Ensure verdict is verified server-side, not client-side."),
]


class DexAnalyzer:
    def __init__(self, apk_path: str, extracted_dir: str):
        self.apk_path      = apk_path
        self.extracted_dir = extracted_dir
        self.findings: List[Finding] = []
        self.call_graph_built = False
        self.taint_paths: List[dict] = []   # exposed in result for reporting

    def analyze(self) -> None:
        log.info("DEX bytecode analysis…")
        success = self._try_androguard_analysis()
        if not success:
            log.info("DEX analysis: androguard unavailable — running smali fallback")
            self._smali_fallback()
        log.info(f"DEX analysis: {len(self.findings)} finding(s) | call graph: {self.call_graph_built}")

    # ── Full androguard analysis ───────────────────────────────────────────────

    def _try_androguard_analysis(self) -> bool:
        try:
            from androguard.misc import AnalyzeAPK
            from androguard.core.analysis.analysis import Analysis
        except ImportError:
            return False

        try:
            apk, dex_list, analysis = AnalyzeAPK(self.apk_path)
            self.call_graph_built = True
            log.info(f"  Call graph: {analysis.get_call_graph().number_of_nodes()} nodes")

            self._check_dangerous_api_calls(analysis)
            self._taint_analysis(analysis)
            self._check_crypto_usage(analysis)
            return True
        except Exception as e:
            log.debug(f"Androguard full analysis error: {e}")
            return False

    def _check_dangerous_api_calls(self, analysis) -> None:
        seen: Set[str] = set()
        for cls_pattern, method_name, desc, sev, owasp, cwe, fix in DANGEROUS_APIS:
            # Normalize class pattern to androguard format
            cls_search = cls_pattern.rstrip(";").lstrip("L").replace("/", ".")
            try:
                for meth in analysis.get_methods():
                    m = meth.get_method()
                    # Check if this method calls the dangerous API
                    for _, call, _ in meth.get_xref_to():
                        callee_cls  = call.get_class_name()
                        callee_name = call.get_name()
                        if cls_pattern in callee_cls and callee_name == method_name:
                            key = f"{callee_cls}{callee_name}{m.get_class_name()}"
                            if key in seen:
                                continue
                            seen.add(key)
                            caller = f"{m.get_class_name()}->{m.get_name()}"
                            self.findings.append(Finding(
                                rule_id=f"DEX_API_{method_name.upper()[:20]}",
                                category="DEX Bytecode Analysis",
                                severity=sev,
                                title=f"Dangerous API: {cls_pattern.split('/')[-1].rstrip(';')}.{method_name}()",
                                description=desc,
                                evidence=f"Called from: {caller}",
                                file_path=m.get_class_name().replace(";","").lstrip("L").replace("/","/") + ".smali",
                                owasp=owasp,
                                cwe=cwe,
                                confidence="HIGH",
                                remediation=fix,
                            ))
            except Exception:
                continue

    def _taint_analysis(self, analysis) -> None:
        """
        Lightweight taint tracking:
        For each taint source, find its callers.
        For each caller, check if any method in its transitive call chain
        reaches a taint sink within N hops.
        """
        MAX_HOPS = 4
        seen_paths: Set[str] = set()

        source_methods = {}
        for cls_pat, meth_name in TAINT_SOURCES:
            try:
                for meth in analysis.get_methods():
                    if cls_pat in meth.get_method().get_class_name() and \
                       meth.get_method().get_name() == meth_name:
                        source_methods[f"{meth.get_method().get_class_name()}{meth_name}"] = meth
            except Exception:
                continue

        for src_key, src_meth in source_methods.items():
            # Get callers of this source
            try:
                callers = [caller for caller, _, _ in src_meth.get_xref_from()]
            except Exception:
                continue

            for caller_ref in callers[:20]:  # limit breadth
                self._dfs_to_sink(
                    analysis, caller_ref, depth=0, max_depth=MAX_HOPS,
                    path=[src_key], seen_paths=seen_paths
                )

    def _dfs_to_sink(self, analysis, method_ref, depth: int, max_depth: int,
                     path: List[str], seen_paths: Set[str]) -> None:
        if depth >= max_depth:
            return
        try:
            meth_analysis = analysis.get_method(method_ref)
            if meth_analysis is None:
                return
            for _, callee, _ in meth_analysis.get_xref_to():
                callee_cls  = callee.get_class_name()
                callee_name = callee.get_name()
                for sink_cls, sink_meth, vuln, sev, owasp, cwe in TAINT_SINKS:
                    if sink_cls in callee_cls and callee_name == sink_meth:
                        path_key = f"{path[0]}→{callee_cls}{callee_name}"
                        if path_key in seen_paths:
                            continue
                        seen_paths.add(path_key)
                        caller_name = f"{method_ref.get_class_name()}->{method_ref.get_name()}"
                        sink_name   = f"{callee_cls.split('/')[-1].rstrip(';')}.{callee_name}()"
                        self.taint_paths.append({
                            "source": path[0],
                            "sink": path_key,
                            "hops": depth + 1,
                        })
                        self.findings.append(Finding(
                            rule_id=f"DEX_TAINT_{vuln.upper().replace(' ','_')[:20]}",
                            category="DEX Taint Analysis",
                            severity=sev,
                            title=f"Taint Flow: User Input → {vuln}",
                            description=(
                                f"Data from a user-controlled source flows {depth+1} hop(s) "
                                f"into {sink_name} without apparent sanitisation. "
                                f"Vulnerability type: {vuln}."
                            ),
                            evidence=f"{caller_name} → {sink_name}",
                            file_path=method_ref.get_class_name().lstrip("L").rstrip(";").replace("/", "/") + ".smali",
                            owasp=owasp,
                            cwe=cwe,
                            cvss=7.5,
                            confidence="MEDIUM",
                            remediation=(
                                f"Sanitise and validate all user input before passing to {sink_name}. "
                                "Use parameterised queries for SQL, avoid shell execution, "
                                "encode output for WebView."
                            ),
                        ))
            # Continue DFS
            for _, callee, _ in meth_analysis.get_xref_to():
                callee_analysis = analysis.get_method(callee)
                if callee_analysis:
                    self._dfs_to_sink(
                        analysis, callee, depth + 1, max_depth,
                        path + [f"{callee.get_class_name()}{callee.get_name()}"],
                        seen_paths,
                    )
        except Exception:
            return

    def _check_crypto_usage(self, analysis) -> None:
        """Find all Cipher.getInstance() calls and extract the algorithm argument."""
        weak_algos = {"DES", "3DES", "DESede", "RC4", "ARCFOUR", "Blowfish"}
        seen: Set[str] = set()
        try:
            for meth in analysis.get_methods():
                for _, callee, _ in meth.get_xref_to():
                    if "Cipher" in callee.get_class_name() and callee.get_name() == "getInstance":
                        # Try to extract the string constant argument via bytecode
                        m = meth.get_method()
                        try:
                            code = m.get_code()
                            if code is None:
                                continue
                            for instr in code.get_bc().get_instructions():
                                if instr.get_name() == "const-string":
                                    algo = str(instr.get_output()).strip("'\" ")
                                    base_algo = algo.split("/")[0].upper()
                                    if base_algo in {w.upper() for w in weak_algos}:
                                        key = f"cipher_{algo}_{m.get_class_name()}"
                                        if key in seen:
                                            continue
                                        seen.add(key)
                                        self.findings.append(Finding(
                                            rule_id=f"DEX_WEAK_CIPHER_{base_algo}",
                                            category="DEX Bytecode Analysis",
                                            severity=Severity.HIGH,
                                            title=f"Weak Cipher Confirmed by Bytecode: {algo}",
                                            description=(
                                                f"Bytecode analysis confirmed Cipher.getInstance(\"{algo}\") "
                                                f"in {m.get_class_name()}. This is not a regex guess."
                                            ),
                                            evidence=f'Cipher.getInstance("{algo}")',
                                            file_path=m.get_class_name().lstrip("L").rstrip(";") + ".smali",
                                            owasp="M10",
                                            cwe="CWE-327",
                                            cvss=7.5,
                                            confidence="HIGH",
                                            remediation="Replace with AES/GCM/NoPadding. Use 256-bit keys.",
                                        ))
                        except Exception:
                            continue
        except Exception:
            pass

    # ── Smali text fallback (when androguard full analysis is unavailable) ─────

    def _smali_fallback(self) -> None:
        """
        Parse smali files for invoke- opcodes to detect dangerous API calls.
        Less precise than call graph but works without androguard analysis objects.
        """
        smali_dirs = [
            os.path.join(self.extracted_dir, d)
            for d in os.listdir(self.extracted_dir)
            if d.startswith("smali") and os.path.isdir(os.path.join(self.extracted_dir, d))
        ]
        seen: Set[str] = set()
        invoke_re = re.compile(
            r'invoke-\w+\s+\{[^}]*\},\s*(L[^;]+;)->([\w<>$]+)\s*\(', re.MULTILINE
        )

        for smali_dir in smali_dirs:
            for root, _, files in os.walk(smali_dir):
                for fname in files:
                    if not fname.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, fname)
                    rel   = os.path.relpath(fpath, self.extracted_dir)
                    try:
                        content = open(fpath, errors="replace").read()
                    except OSError:
                        continue

                    for m in invoke_re.finditer(content):
                        cls_name  = m.group(1)
                        meth_name = m.group(2)
                        for cls_pat, api_meth, desc, sev, owasp, cwe, fix in DANGEROUS_APIS:
                            if cls_pat in cls_name and api_meth == meth_name:
                                key = f"{cls_name}{meth_name}{rel}"
                                if key in seen:
                                    continue
                                seen.add(key)
                                line_no = content[:m.start()].count("\n") + 1
                                self.findings.append(Finding(
                                    rule_id=f"DEX_API_{meth_name.upper()[:20]}",
                                    category="DEX Bytecode Analysis",
                                    severity=sev,
                                    title=f"Dangerous API: {cls_name.split('/')[-1].rstrip(';')}.{meth_name}()",
                                    description=desc,
                                    evidence=m.group(0)[:120],
                                    file_path=rel,
                                    line_number=line_no,
                                    owasp=owasp,
                                    cwe=cwe,
                                    confidence="HIGH",
                                    remediation=fix,
                                ))
