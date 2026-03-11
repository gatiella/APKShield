"""
apkshield/rules/permissions.py
Android permission risk database.
Each entry: permission_name -> (Severity, description, remediation)
"""
from apkshield.models import Severity

DANGEROUS_PERMISSIONS = {
    # ── Telephony / SMS ────────────────────────────────────────────────────────
    "android.permission.READ_SMS":
        (Severity.HIGH, "Reads all SMS messages — can expose OTPs and 2FA codes.",
         "Remove if not required. Justify in Play Store data safety form."),
    "android.permission.SEND_SMS":
        (Severity.HIGH, "Can send SMS without user confirmation — toll fraud risk.",
         "Use intent-based SMS sending so the user approves each message."),
    "android.permission.RECEIVE_SMS":
        (Severity.HIGH, "Intercepts all incoming SMS including OTPs.",
         "Use the SMS Retriever API for OTP auto-fill instead."),
    "android.permission.READ_CALL_LOG":
        (Severity.HIGH, "Reads full call history.", "Remove unless core functionality."),
    "android.permission.WRITE_CALL_LOG":
        (Severity.MEDIUM, "Can modify call history.", "Remove unless necessary."),
    "android.permission.PROCESS_OUTGOING_CALLS":
        (Severity.HIGH, "Intercepts and redirects outgoing calls.", "Remove unless a dialler app."),

    # ── Contacts / Accounts ────────────────────────────────────────────────────
    "android.permission.READ_CONTACTS":
        (Severity.MEDIUM, "Can read the entire contacts list.", "Request only when actively needed, explain why."),
    "android.permission.WRITE_CONTACTS":
        (Severity.MEDIUM, "Can modify or delete contacts.", "Scope access to only required fields."),
    "android.permission.GET_ACCOUNTS":
        (Severity.MEDIUM, "Enumerates all accounts on the device.", "Use AccountManager with specific account type."),

    # ── Storage ────────────────────────────────────────────────────────────────
    "android.permission.READ_EXTERNAL_STORAGE":
        (Severity.LOW, "Reads all external storage.", "Use scoped storage APIs (Android 10+)."),
    "android.permission.WRITE_EXTERNAL_STORAGE":
        (Severity.MEDIUM, "Writes to shared external storage.", "Use app-specific directories or MediaStore."),
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        (Severity.HIGH, "Broad access to all external storage — requires Play Store review.",
         "Use scoped storage. Only file manager apps qualify for this permission."),
    "android.permission.READ_MEDIA_IMAGES":
        (Severity.MEDIUM, "Reads images from the media store.", "Use photo picker API where possible."),
    "android.permission.READ_MEDIA_VIDEO":
        (Severity.MEDIUM, "Reads videos from the media store.", "Use photo picker API where possible."),
    "android.permission.READ_MEDIA_AUDIO":
        (Severity.MEDIUM, "Reads audio files from the media store.", "Request only when needed."),

    # ── Camera / Microphone ───────────────────────────────────────────────────
    "android.permission.CAMERA":
        (Severity.MEDIUM, "Accesses the camera.", "Use camera intents when full camera access is not needed."),
    "android.permission.RECORD_AUDIO":
        (Severity.HIGH, "Records microphone audio at any time.", "Request only during active recording; explain to users."),

    # ── Location ──────────────────────────────────────────────────────────────
    "android.permission.ACCESS_FINE_LOCATION":
        (Severity.MEDIUM, "GPS-level precise location.", "Use coarse location where precision is not required."),
    "android.permission.ACCESS_COARSE_LOCATION":
        (Severity.LOW, "Approximate network-based location.", "Explain use to users; minimise collection."),
    "android.permission.ACCESS_BACKGROUND_LOCATION":
        (Severity.HIGH, "Tracks location even when app is not in use.",
         "Requires explicit user consent (Android 10+). Only use if truly necessary."),

    # ── Sensors / Biometrics ──────────────────────────────────────────────────
    "android.permission.BODY_SENSORS":
        (Severity.MEDIUM, "Accesses health sensors (heart rate, etc.).", "Justify and minimise data retention."),
    "android.permission.USE_BIOMETRIC":
        (Severity.MEDIUM, "Uses biometric authentication (fingerprint/face).", "Acceptable for auth; never store biometric data."),
    "android.permission.USE_FINGERPRINT":
        (Severity.MEDIUM, "Legacy fingerprint permission.", "Migrate to USE_BIOMETRIC."),

    # ── Bluetooth / NFC ───────────────────────────────────────────────────────
    "android.permission.BLUETOOTH":
        (Severity.LOW, "Legacy Bluetooth access.", "Migrate to granular Bluetooth permissions (Android 12+)."),
    "android.permission.BLUETOOTH_SCAN":
        (Severity.MEDIUM, "Scans for nearby Bluetooth devices — can be used for tracking.", "Add neverForLocation=true if not using for location."),
    "android.permission.BLUETOOTH_CONNECT":
        (Severity.MEDIUM, "Connects to paired Bluetooth devices.", "Request only when establishing connections."),
    "android.permission.NFC":
        (Severity.MEDIUM, "Reads NFC tags.", "Acceptable for NFC apps; be cautious with payment data."),

    # ── Phone ─────────────────────────────────────────────────────────────────
    "android.permission.READ_PHONE_STATE":
        (Severity.MEDIUM, "Reads IMEI, network state, and call status.", "Avoid; use alternatives that don't expose IMEI."),
    "android.permission.READ_PHONE_NUMBERS":
        (Severity.MEDIUM, "Reads the device phone number.", "Use only if absolutely required."),
    "android.permission.CALL_PHONE":
        (Severity.HIGH, "Makes calls without user confirmation.", "Use Intent.ACTION_DIAL so user confirms."),
    "android.permission.ANSWER_PHONE_CALLS":
        (Severity.HIGH, "Programmatically answers calls.", "Only for dialler/call apps."),
    "android.permission.ADD_VOICEMAIL":
        (Severity.MEDIUM, "Adds voicemail entries.", "Remove unless you are a voicemail app."),

    # ── Package / App Management ──────────────────────────────────────────────
    "android.permission.INSTALL_PACKAGES":
        (Severity.CRITICAL, "Silently installs other APKs — extremely high abuse potential.",
         "Remove entirely unless this is a device owner/MDM app. Never use in consumer apps."),
    "android.permission.DELETE_PACKAGES":
        (Severity.HIGH, "Uninstalls other apps silently.", "Remove unless device management app."),
    "android.permission.REQUEST_INSTALL_PACKAGES":
        (Severity.HIGH, "Enables sideloading via unknown sources.", "Remove if not distributing APKs (e.g. update mechanism)."),

    # ── System / Overlay / Admin ──────────────────────────────────────────────
    "android.permission.SYSTEM_ALERT_WINDOW":
        (Severity.HIGH, "Draws over other apps — used in tapjacking and phishing overlays.",
         "Use only if essential (e.g. chat heads). Explain clearly to users."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        (Severity.CRITICAL, "Full UI observation and control — highest-risk permission in Android.",
         "Justification required for Play Store. Users must manually grant. Audit all usage."),
    "android.permission.BIND_DEVICE_ADMIN":
        (Severity.CRITICAL, "Full device administrator access.", "Only for MDM/EMM solutions. Requires explicit user activation."),
    "android.permission.RECEIVE_BOOT_COMPLETED":
        (Severity.MEDIUM, "Starts automatically after reboot.", "Minimise work done at boot. Ensure it's necessary."),
    "android.permission.FOREGROUND_SERVICE":
        (Severity.LOW, "Runs a persistent foreground service.", "Use WorkManager where possible instead."),

    # ── Network ───────────────────────────────────────────────────────────────
    "android.permission.INTERNET":
        (Severity.INFO, "Accesses the internet.", "Expected for most apps. Ensure all traffic uses HTTPS."),
    "android.permission.CHANGE_NETWORK_STATE":
        (Severity.MEDIUM, "Can enable/disable network connectivity.", "Remove if not needed."),
    "android.permission.CHANGE_WIFI_STATE":
        (Severity.MEDIUM, "Can connect or disconnect from Wi-Fi networks.", "Remove if not needed."),
    "android.permission.ACCESS_WIFI_STATE":
        (Severity.LOW, "Reads Wi-Fi state and SSID.", "Acceptable for network-aware apps."),

    # ── Misc ──────────────────────────────────────────────────────────────────
    "android.permission.VIBRATE":
        (Severity.INFO, "Controls device vibration.", "No risk."),
    "android.permission.WAKE_LOCK":
        (Severity.LOW, "Prevents the device from sleeping.", "Use WorkManager; release locks promptly."),
    "android.permission.SCHEDULE_EXACT_ALARM":
        (Severity.LOW, "Schedules precise alarms.", "Requires user approval (Android 12+)."),
    "android.permission.USE_EXACT_ALARM":
        (Severity.LOW, "Alternative exact alarm permission.", "Use only for calendar/clock apps."),
    "com.google.android.c2dm.permission.RECEIVE":
        (Severity.INFO, "Receives Firebase/GCM push notifications.", "Standard for push; no risk."),
}
