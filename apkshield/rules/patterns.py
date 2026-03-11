"""
apkshield/rules/patterns.py

All regex-based detection rule sets.
Each rule is a tuple:
  (name, regex, Severity, owasp_id, cwe_id, remediation, confidence)

confidence: "HIGH" | "MEDIUM" | "LOW"
"""
from apkshield.models import Severity

# ── URL whitelist: never flag these as cleartext HTTP ─────────────────────────
HTTP_WHITELIST = {
    "schemas.android.com",
    "www.w3.org",
    "purl.org",
    "ns.adobe.com",
    "xml.org",
    "opengis.net",
    "ogc.org",
    "dublincore.org",
    "xmlns.com",
    "json-schema.org",
    "iana.org",
}

# ── Skip values: obviously fake / placeholder ─────────────────────────────────
PLACEHOLDER_FRAGMENTS = [
    "example", "placeholder", "your_key", "yourkey", "changeme",
    "insert_here", "xxxxxxx", "000000", "aaaaaa", "test123",
    "dummy", "sample", "foobar", "TODO", "FIXME",
]

# ─────────────────────────────────────────────────────────────────────────────
# SECRETS
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID",
     r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
     Severity.CRITICAL, "M1", "CWE-798", "Rotate the key immediately via AWS IAM. Never embed credentials in code.", "HIGH"),

    ("AWS Secret Access Key",
     r'(?i)aws[_\-\s\.]{0,10}secret[_\-\s\.]{0,10}(key|access)[_\-\s\.]{0,5}[=:"\s\']+[A-Za-z0-9/+=]{40}(?=[^A-Za-z0-9/+=]|$)',
     Severity.CRITICAL, "M1", "CWE-798", "Rotate via AWS IAM. Use IAM roles or AWS Secrets Manager instead.", "HIGH"),

    ("AWS ARN",
     r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\']{3,}',
     Severity.HIGH, "M1", "CWE-312", "Remove ARNs from client-side code. Keep infrastructure references server-side.", "HIGH"),

    # Google
    ("Google API Key",
     r'AIza[0-9A-Za-z\-_]{35}',
     Severity.HIGH, "M1", "CWE-798", "Restrict the key in Google Cloud Console by Android package name + SHA-1. Never embed server-side keys.", "HIGH"),

    ("Google OAuth Access Token",
     r'ya29\.[0-9A-Za-z\-_]{30,}',
     Severity.CRITICAL, "M1", "CWE-798", "Revoke token immediately. Use OAuth 2.0 with PKCE; never cache tokens in code.", "HIGH"),

    ("Google Service Account JSON",
     r'"type"\s*:\s*"service_account"',
     Severity.CRITICAL, "M1", "CWE-798", "Remove service account JSON from APK. Use Workload Identity or server-to-server auth.", "HIGH"),

    # Firebase
    ("Firebase Realtime DB URL",
     r'https://[a-z0-9\-]+\.firebaseio\.com',
     Severity.MEDIUM, "M1", "CWE-312", "Ensure Firebase security rules require authentication. Audit public read/write rules.", "HIGH"),

    # Stripe
    ("Stripe Secret Key (live)",
     r'sk_live_[0-9a-zA-Z]{24,}',
     Severity.CRITICAL, "M1", "CWE-798", "Rotate immediately at stripe.com/keys. Secret keys must only exist server-side.", "HIGH"),

    ("Stripe Publishable Key (live)",
     r'pk_live_[0-9a-zA-Z]{24,}',
     Severity.HIGH, "M1", "CWE-312", "Publishable keys are lower risk but confirm no secret key is also present.", "HIGH"),

    ("Stripe Test Key",
     r'sk_test_[0-9a-zA-Z]{24,}',
     Severity.MEDIUM, "M1", "CWE-798", "Remove test keys from production builds. Use build variants to manage keys.", "HIGH"),

    # JWT
    ("JWT Token",
     r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}',
     Severity.HIGH, "M1", "CWE-312", "Never hardcode JWTs. Obtain tokens at runtime via secure auth flows.", "MEDIUM"),

    # Credentials
    ("Hardcoded Password",
     r'(?i)\b(password|passwd|pwd|pass)\s*[=:]+\s*["\']([^"\'\\]{4,})["\']',
     Severity.HIGH, "M1", "CWE-798", "Remove hardcoded passwords. Use Android Keystore or a secrets vault.", "MEDIUM"),

    ("Hardcoded Secret / API Secret",
     r'(?i)\b(secret|api_secret|client_secret|app_secret)\s*[=:]+\s*["\']([^"\'\\]{8,})["\']',
     Severity.HIGH, "M1", "CWE-798", "Rotate the secret. Never store secrets in source code or APK resources.", "MEDIUM"),

    ("Hardcoded Auth Token",
     r'(?i)\b(token|auth_token|access_token|bearer)\s*[=:]+\s*["\']([A-Za-z0-9\-_.]{16,})["\']',
     Severity.HIGH, "M1", "CWE-798", "Obtain tokens at runtime. Store in EncryptedSharedPreferences if caching is required.", "MEDIUM"),

    # Private Keys
    ("RSA Private Key",   r'-----BEGIN RSA PRIVATE KEY-----', Severity.CRITICAL, "M1", "CWE-321",
     "Remove immediately. Private keys must never be bundled in an APK.", "HIGH"),
    ("PKCS8 Private Key", r'-----BEGIN PRIVATE KEY-----',     Severity.CRITICAL, "M1", "CWE-321",
     "Remove immediately. Use Android Keystore for key material.", "HIGH"),
    ("EC Private Key",    r'-----BEGIN EC PRIVATE KEY-----',  Severity.CRITICAL, "M1", "CWE-321",
     "Remove immediately. Use Android Keystore for key material.", "HIGH"),
    ("SSH Private Key",   r'-----BEGIN OPENSSH PRIVATE KEY-----', Severity.CRITICAL, "M1", "CWE-321",
     "Remove immediately. SSH keys must never be in client-side code.", "HIGH"),

    # GitHub / GitLab / CI tokens
    ("GitHub Personal Access Token",
     r'ghp_[A-Za-z0-9]{36}',
     Severity.CRITICAL, "M1", "CWE-798", "Revoke at github.com/settings/tokens immediately.", "HIGH"),

    ("GitHub Token (generic)",
     r'(?i)github[_\-\s\.]*token\s*[=:"\s\']+[A-Za-z0-9_]{35,45}',
     Severity.HIGH, "M1", "CWE-798", "Revoke and rotate. Use GitHub Actions secrets or OIDC instead.", "MEDIUM"),

    ("GitLab Personal Access Token",
     r'glpat-[A-Za-z0-9\-_]{20}',
     Severity.HIGH, "M1", "CWE-798", "Revoke at gitlab.com/-/user_settings/personal_access_tokens.", "HIGH"),

    # Slack / Twilio / SendGrid
    ("Slack Bot / User Token",
     r'xox[baprs]-[0-9A-Za-z\-]{10,}',
     Severity.HIGH, "M1", "CWE-798", "Revoke at api.slack.com/apps. Use Slack's OAuth flow.", "HIGH"),

    ("Slack Webhook URL",
     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
     Severity.HIGH, "M1", "CWE-798", "Rotate the webhook URL. Never expose Slack webhooks in client code.", "HIGH"),

    ("Twilio Account SID",
     r'\bAC[a-fA-F0-9]{32}\b',
     Severity.HIGH, "M1", "CWE-798", "Move Twilio logic server-side. Rotate at console.twilio.com.", "HIGH"),

    ("SendGrid API Key",
     r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
     Severity.HIGH, "M1", "CWE-798", "Revoke at app.sendgrid.com/settings/api_keys.", "HIGH"),

    # Azure
    ("Azure Storage Connection String",
     r'DefaultEndpointsProtocol=https;AccountName=[^;]{3,};AccountKey=[A-Za-z0-9+/=]{50,}',
     Severity.CRITICAL, "M1", "CWE-798", "Rotate at Azure portal. Use Managed Identity or SAS tokens with minimal permissions.", "HIGH"),

    ("Azure SAS Token",
     r'sv=20\d\d-\d\d-\d\d&s[se]=[a-zA-Z&=%0-9\-]+sig=[A-Za-z0-9%+/=]+',
     Severity.HIGH, "M1", "CWE-798", "Revoke and regenerate SAS token with a short expiry server-side.", "HIGH"),

    # Database
    ("Database Connection String",
     r'(?i)(jdbc|mongodb(\+srv)?|mysql|postgresql|redis|amqp|mssql)://[^\s"\'<>\]]{10,}',
     Severity.HIGH, "M1", "CWE-312", "Move DB connection strings to server-side config. Never embed in client apps.", "HIGH"),

    ("Database Password Field",
     r'(?i)\b(db_pass|db_password|database_password|mysql_password)\s*[=:]+\s*["\']([^"\'\\]{4,})["\']',
     Severity.CRITICAL, "M1", "CWE-798", "Remove immediately. Databases must never be directly accessible from mobile clients.", "HIGH"),

    # Generic high-entropy API key
    ("Generic API Key",
     r'(?i)\b(api_key|apikey|access_key|secret_key)\s*[=:]+\s*["\']([A-Za-z0-9+/=_\-]{32,})["\']',
     Severity.HIGH, "M1", "CWE-798", "Store API keys securely server-side. Use backend proxying to protect them.", "MEDIUM"),

    # Private network hints (low severity, informational)
    ("Internal IPv4 Address",
     r'(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
     Severity.LOW, "M8", "CWE-312", "Remove internal IP addresses from builds. Use DNS names and environment configs.", "MEDIUM"),
]

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK SECURITY
# ─────────────────────────────────────────────────────────────────────────────
NETWORK_PATTERNS = [
    ("Cleartext HTTP URL",
     r'\bhttp://(?!(' + '|'.join(HTTP_WHITELIST).replace('.', r'\.') + r'))[a-zA-Z0-9\-\.]{4,}\.[a-zA-Z]{2,}(?:/[^\s"\']*)?',
     Severity.MEDIUM, "M5", "CWE-319",
     "Replace with https://. Enable Network Security Config to block all cleartext traffic.", "HIGH"),

    ("Cleartext Traffic Permitted in Manifest",
     r'android:usesCleartextTraffic\s*=\s*["\']true["\']',
     Severity.HIGH, "M5", "CWE-319",
     "Set android:usesCleartextTraffic=false and define a Network Security Config.", "HIGH"),

    ("Trust-All TrustManager",
     r'(?i)(TrustAllX509TrustManager|ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NullHostnameVerifier)',
     Severity.CRITICAL, "M5", "CWE-295",
     "Remove trust-all implementations. Validate the full certificate chain.", "HIGH"),

    ("Empty checkServerTrusted / getAcceptedIssuers",
     r'(?i)(checkServerTrusted|getAcceptedIssuers)\s*\([^)]*\)\s*\{?\s*(return null;?)?\s*\}',
     Severity.CRITICAL, "M5", "CWE-295",
     "Implement proper X509TrustManager. Never leave these methods empty.", "HIGH"),

    ("SSL Error Ignored in WebView",
     r'(?i)onReceivedSslError\s*\([^)]*\)[^{]*\{[^}]*\.proceed\(\)',
     Severity.CRITICAL, "M5", "CWE-295",
     "Call handler.cancel() in onReceivedSslError. Never call proceed() on SSL errors.", "HIGH"),

    ("Weak TLS Version",
     r'(?i)(SSLv3|TLSv1[^\.23]|SSLContext\.getInstance\s*\(\s*["\']SSL["\'])',
     Severity.HIGH, "M5", "CWE-326",
     "Enforce TLS 1.2 minimum via Network Security Config. Prefer TLS 1.3.", "HIGH"),

    ("HostnameVerifier Accepts All",
     r'(?i)setHostnameVerifier\s*\(\s*(ALLOW_ALL_HOSTNAME_VERIFIER|new\s+\w*AllowAll\w*)',
     Severity.CRITICAL, "M5", "CWE-295",
     "Use the default HostnameVerifier or implement strict validation.", "HIGH"),

    ("WebView JavaScript Enabled",
     r'setJavaScriptEnabled\s*\(\s*true\s*\)',
     Severity.MEDIUM, "M8", "CWE-749",
     "Disable JavaScript unless required. If enabled, restrict origins and avoid addJavascriptInterface.", "HIGH"),

    ("WebView File Access Enabled",
     r'setAllowFileAccess\s*\(\s*true\s*\)',
     Severity.HIGH, "M8", "CWE-284",
     "Set setAllowFileAccess(false). Use content:// URIs with a FileProvider instead.", "HIGH"),

    ("WebView Universal File Access",
     r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
     Severity.CRITICAL, "M8", "CWE-284",
     "Set to false. This allows cross-origin data theft via file:// URIs.", "HIGH"),

    ("addJavascriptInterface Usage",
     r'addJavascriptInterface\s*\(',
     Severity.MEDIUM, "M4", "CWE-749",
     "Ensure only trusted content is loaded. Add @JavascriptInterface only to required methods. Requires API 17+.", "HIGH"),

    ("Certificate Pinning Disabled in OkHttp",
     r'(?i)hostnameVerifier\s*\(\s*\{.*?true.*?\}',
     Severity.CRITICAL, "M5", "CWE-295",
     "Use OkHttp CertificatePinner. Never return true unconditionally from HostnameVerifier.", "MEDIUM"),
]

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTOGRAPHY
# ─────────────────────────────────────────────────────────────────────────────
CRYPTO_PATTERNS = [
    ("Broken Cipher - DES",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']DES["/\']',
     Severity.HIGH, "M10", "CWE-327",
     "Replace DES with AES-256-GCM. DES has a 56-bit key — trivially brute-forced.", "HIGH"),

    ("Broken Cipher - 3DES",
     r'(?i)Cipher\.getInstance\s*\(\s*["\']DESede',
     Severity.HIGH, "M10", "CWE-327",
     "Replace 3DES with AES-256-GCM. 3DES is deprecated (NIST SP 800-131A).", "HIGH"),

    ("Weak Hash - MD5",
     r'(?i)MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
     Severity.HIGH, "M10", "CWE-327",
     "Replace MD5 with SHA-256 or SHA-3. MD5 is cryptographically broken.", "HIGH"),

    ("Weak Hash - SHA-1",
     r'(?i)MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
     Severity.MEDIUM, "M10", "CWE-327",
     "Replace SHA-1 with SHA-256. SHA-1 collision attacks are practical.", "HIGH"),

    ("ECB Mode (No Diffusion)",
     r'(?i)Cipher\.getInstance\s*\(\s*["\'][^"\']*[/\\]ECB',
     Severity.HIGH, "M10", "CWE-327",
     "Use AES/GCM/NoPadding. ECB mode is deterministic and leaks patterns.", "HIGH"),

    ("RC4 Stream Cipher",
     r'(?i)\b(RC4|ARCFOUR)\b',
     Severity.HIGH, "M10", "CWE-327",
     "Replace RC4 with AES-256-GCM. RC4 has multiple practical cryptographic weaknesses.", "HIGH"),

    ("Insecure Random (not SecureRandom)",
     r'(?i)\bnew\s+Random\s*\(\s*\)',
     Severity.MEDIUM, "M10", "CWE-338",
     "Use java.security.SecureRandom for any security-sensitive random values.", "HIGH"),

    ("Math.random() for Security",
     r'\bMath\.random\s*\(\s*\)',
     Severity.MEDIUM, "M10", "CWE-338",
     "Math.random() is not cryptographically secure. Use SecureRandom.", "HIGH"),

    ("Static / Zero IV",
     r'(?i)new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[',
     Severity.HIGH, "M10", "CWE-329",
     "Generate a fresh random IV per encryption with SecureRandom. Never reuse IVs.", "HIGH"),

    ("Hardcoded SecretKeySpec",
     r'(?i)new\s+SecretKeySpec\s*\(\s*(["\'][A-Za-z0-9+/=]{16,}["\']|new\s+byte\[\]\s*\{)',
     Severity.CRITICAL, "M10", "CWE-321",
     "Never hardcode encryption keys. Use Android Keystore to generate and store keys securely.", "HIGH"),

    ("BKS KeyStore (not AndroidKeyStore)",
     r'(?i)KeyStore\.getInstance\s*\(\s*["\']BKS["\']',
     Severity.MEDIUM, "M10", "CWE-320",
     "Use KeyStore.getInstance('AndroidKeyStore') for hardware-backed key storage.", "HIGH"),

    ("Low PBKDF2 Iteration Count",
     r'(?i)new\s+PBEKeySpec\s*\([^)]+,\s*[^,]+,\s*([1-9]\d{0,3})\s*,',
     Severity.MEDIUM, "M10", "CWE-916",
     "Use at least 310,000 iterations for PBKDF2-HMAC-SHA256 (OWASP 2023 recommendation).", "MEDIUM"),
]

# ─────────────────────────────────────────────────────────────────────────────
# INJECTION
# ─────────────────────────────────────────────────────────────────────────────
INJECTION_PATTERNS = [
    ("SQL Injection via String Concatenation",
     r'(?i)(rawQuery|execSQL)\s*\([^;)]*\+[^;)]*[,)]',
     Severity.HIGH, "M4", "CWE-89",
     "Use parameterized queries (SQLiteStatement / Room). Never concatenate user input into SQL.", "HIGH"),

    ("Shell Command Injection",
     r'(?i)(Runtime\.getRuntime\s*\(\s*\)\.exec|new\s+ProcessBuilder)\s*\(',
     Severity.HIGH, "M4", "CWE-78",
     "Avoid executing shell commands. If unavoidable, validate and whitelist all inputs strictly.", "HIGH"),

    ("Path Traversal Risk",
     r'(?i)(new\s+File|openFileOutput|FileOutputStream)\s*\([^)]*\+',
     Severity.MEDIUM, "M4", "CWE-22",
     "Validate file paths. Use File.getCanonicalPath() and ensure paths stay within the app sandbox.", "MEDIUM"),

    ("XSS via WebView.loadData / loadUrl",
     r'(?i)(loadUrl|loadData|loadDataWithBaseURL)\s*\([^)]*\+',
     Severity.HIGH, "M4", "CWE-79",
     "Sanitise all content before loading into WebViews. Use encodeURIComponent or safe HTML encoding.", "MEDIUM"),

    ("Log Injection",
     r'(?i)Log\s*\.\s*[deiVw]\s*\([^)]*\+[^)]*\)',
     Severity.LOW, "M9", "CWE-117",
     "Sanitise log messages. Remove sensitive data from logs before release.", "MEDIUM"),

    ("Intent Extra Forwarded Without Validation",
     r'(?i)getIntent\s*\(\s*\)\s*\.(getStringExtra|getIntExtra|getBundleExtra)',
     Severity.MEDIUM, "M4", "CWE-925",
     "Validate all Intent extras before use. Treat them as untrusted input.", "MEDIUM"),

    ("Dynamic Class Loading",
     r'(?i)(DexClassLoader|PathClassLoader|new\s+URLClassLoader)\s*\(',
     Severity.HIGH, "M7", "CWE-470",
     "Audit all dynamic class loading. Verify code integrity before loading external DEX files.", "HIGH"),

    ("JavaScript Interface Injection",
     r'(?i)addJavascriptInterface\s*\([^,]+,\s*["\'][^"\']+["\']',
     Severity.MEDIUM, "M4", "CWE-749",
     "Expose minimal API surface via @JavascriptInterface. Load only trusted content in the WebView.", "HIGH"),
]

# ─────────────────────────────────────────────────────────────────────────────
# INSECURE DATA STORAGE
# ─────────────────────────────────────────────────────────────────────────────
STORAGE_PATTERNS = [
    ("World-Readable / World-Writable File",
     r'(?i)(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)',
     Severity.HIGH, "M9", "CWE-732",
     "Use MODE_PRIVATE. World-accessible files can be read by any app on the device.", "HIGH"),

    ("Sensitive Data in Log",
     r'(?i)Log\s*\.\s*[deiVw]\s*\([^)]*\b(password|token|secret|key|ssn|credit|cvv|pin|auth)\b',
     Severity.HIGH, "M9", "CWE-532",
     "Strip all sensitive values from logs before release. Use BuildConfig.DEBUG guards.", "HIGH"),

    ("External Storage for Sensitive Data",
     r'(?i)getExternalStorage(Directory|FilesDir|PublicDirectory)',
     Severity.MEDIUM, "M9", "CWE-312",
     "Store sensitive data in internal app storage (getFilesDir). External storage is world-readable.", "HIGH"),

    ("Unencrypted SharedPreferences",
     r'(?i)getSharedPreferences\s*\([^)]+\)',
     Severity.LOW, "M9", "CWE-312",
     "Use EncryptedSharedPreferences (Jetpack Security) for any sensitive values.", "LOW"),

    ("SQLite Database Unencrypted",
     r'(?i)(openOrCreateDatabase|SQLiteOpenHelper)',
     Severity.LOW, "M9", "CWE-312",
     "Consider SQLCipher for sensitive databases. Ensure no sensitive plaintext in DB.", "LOW"),

    ("ADB Backup Enabled",
     r'android:allowBackup\s*=\s*["\']true["\']',
     Severity.MEDIUM, "M9", "CWE-312",
     "Set android:allowBackup=false or define a full-backup-content XML with exclusion rules.", "HIGH"),

    ("Sensitive Debug Logging",
     r'(?i)\bSystem\.out\.print(ln)?\s*\([^)]*\b(password|token|secret|key)\b',
     Severity.HIGH, "M9", "CWE-532",
     "Use Android Log API with DEBUG guards. Strip in release builds via ProGuard rules.", "HIGH"),
]

# ─────────────────────────────────────────────────────────────────────────────
# BINARY PROTECTIONS
# ─────────────────────────────────────────────────────────────────────────────
BINARY_PATTERNS = [
    ("Root Detection Absent",
     r'(?i)(RootBeer|isRooted|checkForRoot|detectRoot|isDeviceRooted)',
     Severity.INFO, "M7", "CWE-693",
     "Implement root detection for high-risk apps. Consider SafetyNet/Play Integrity API.", "LOW"),

    ("Debugger Detection Absent",
     r'(?i)(isDebuggerConnected|android\.os\.Debug)',
     Severity.INFO, "M7", "CWE-693",
     "Implement anti-debug checks in security-sensitive flows.", "LOW"),

    ("Reflection Usage",
     r'(?i)(Class\.forName\s*\([^)]*\+|Method\.invoke\s*\()',
     Severity.MEDIUM, "M7", "CWE-470",
     "Audit all reflective calls. Validate class names against a whitelist before loading.", "MEDIUM"),

    ("Pending Intent Without Immutability Flag",
     r'(?i)PendingIntent\.(getActivity|getService|getBroadcast)\s*\([^)]*0\s*\)',
     Severity.MEDIUM, "M1", "CWE-925",
     "Use FLAG_IMMUTABLE (Android 12+) or FLAG_UPDATE_CURRENT. Mutable PendingIntents can be hijacked.", "MEDIUM"),
]

# ─────────────────────────────────────────────────────────────────────────────
# KNOWN THIRD-PARTY SDK FINGERPRINTS
# ─────────────────────────────────────────────────────────────────────────────
SDK_FINGERPRINTS = {
    # Analytics
    "com.facebook.":              ("Facebook SDK",           "Collects device ID, IDFA, and behavioural data across Meta ecosystem."),
    "com.appsflyer.":             ("AppsFlyer",              "Mobile attribution — collects install/event data and device identifiers."),
    "com.adjust.sdk":             ("Adjust",                 "Mobile attribution — collects install/event data."),
    "com.onesignal.":             ("OneSignal",              "Push notification SDK."),
    "com.braze.":                 ("Braze (Appboy)",         "Customer engagement — collects behavioural analytics."),
    "io.branch.":                 ("Branch.io",              "Deep linking and attribution — collects device data."),
    "com.amplitude.":             ("Amplitude",              "Product analytics SDK."),
    "com.mixpanel.":              ("Mixpanel",               "Product analytics SDK."),
    "com.segment.":               ("Segment",                "Data pipeline — routes events to multiple vendors."),
    "com.google.firebase.":       ("Firebase",               "Google analytics, crash reporting, push notifications."),
    "com.crashlytics.":           ("Crashlytics (legacy)",   "Crash reporting. Migrate to Firebase Crashlytics."),
    "io.sentry.":                 ("Sentry",                 "Error and performance monitoring."),
    "com.bugsnag.":               ("Bugsnag",                "Error monitoring SDK."),
    # Ad networks
    "com.mopub.":                 ("MoPub (DEPRECATED)",     "Deprecated March 2023 — unmaintained, no security patches."),
    "com.unity3d.ads":            ("Unity Ads",              "Ad SDK for mobile games."),
    "com.ironsource.":            ("IronSource",             "Ad mediation — routes to multiple networks, multiplying data exposure."),
    "com.google.android.gms.ads": ("Google Mobile Ads (AdMob)", "AdMob — collects GAID, device info, and interests."),
    "com.chartboost.":            ("Chartboost",             "Game ad SDK — COPPA compliance required for children's apps."),
    "com.applovin.":              ("AppLovin",               "Ad network and MAX mediation."),
    "com.vungle.":                ("Vungle / Liftoff",       "Video ad network."),
    "com.startapp.":              ("StartApp",               "HIGH RISK — history of excessive location/device data collection."),
    "com.inmobi.":                ("InMobi",                 "Ad network with GDPR consent integration."),
    "net.pubnative.":             ("PubNative / Verve",      "Contextual advertising network."),
    # Dev / ops
    "net.hockeyapp.":             ("HockeyApp (legacy)",     "Deprecated — migrate to App Center or Firebase."),
    "com.microsoft.appcenter.":   ("Microsoft App Center",   "Crash reporting and analytics SDK."),
    # Payments
    "com.stripe.android":         ("Stripe Android SDK",     "Payment processing. Ensure no secret keys in app."),
    "com.paypal.android":         ("PayPal Android SDK",     "Payment processing."),
    "io.revenuecat.":             ("RevenueCat",             "IAP management with server-side validation."),
    # IAP
    "com.android.billingclient.": ("Google Play Billing",    "In-app purchases and subscriptions."),
    "com.android.vending.billing":("Google Play Billing (legacy AIDL)", "Legacy IAP interface."),
    "com.amazon.device.iap.":     ("Amazon IAP",             "Amazon Appstore in-app purchasing."),
}
