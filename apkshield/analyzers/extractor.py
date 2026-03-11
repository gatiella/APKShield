"""
apkshield/analyzers/extractor.py
APK extraction, file enumeration, and hash computation.
"""
from __future__ import annotations
import hashlib
import os
import zipfile
from pathlib import Path
from typing import List, Tuple

from apkshield import logger

log = logger.get()

TEXT_EXTENSIONS = {
    ".smali", ".java", ".kt", ".xml", ".json", ".txt",
    ".properties", ".gradle", ".js", ".html", ".htm",
    ".cfg", ".conf", ".yml", ".yaml", ".sh", ".py",
    ".rb", ".php", ".config", ".pem", ".crt", ".key",
    ".toml", ".ini", ".env", ".proto",
}


class APKExtractor:
    def __init__(self, apk_path: str, work_dir: str):
        self.apk_path = apk_path
        self.work_dir = work_dir
        self.extracted_dir = os.path.join(work_dir, "extracted")
        os.makedirs(self.extracted_dir, exist_ok=True)

    # ── Extraction ────────────────────────────────────────────────────────────

    def extract(self) -> bool:
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                # Safety check: skip path-traversal entries
                for member in z.namelist():
                    member_path = os.path.realpath(
                        os.path.join(self.extracted_dir, member)
                    )
                    if not member_path.startswith(
                        os.path.realpath(self.extracted_dir) + os.sep
                    ):
                        log.warning(f"Skipping unsafe ZIP entry: {member}")
                        continue
                    z.extract(member, self.extracted_dir)
            log.info(f"Extracted APK → {self.extracted_dir}")
            return True
        except Exception as e:
            log.error(f"APK extraction failed: {e}")
            return False

    # ── File enumeration ──────────────────────────────────────────────────────

    def all_files(self) -> List[str]:
        result = []
        for root, _, names in os.walk(self.extracted_dir):
            for name in names:
                result.append(os.path.join(root, name))
        return result

    def text_files(self) -> List[str]:
        """Return files likely to contain readable text (smali, XML, JSON, etc.)."""
        result = []
        for fpath in self.all_files():
            ext = Path(fpath).suffix.lower()
            if ext in TEXT_EXTENSIONS:
                result.append(fpath)
                continue
            # Heuristic: no NUL bytes in first 512 bytes → probably text
            try:
                with open(fpath, "rb") as fh:
                    if b"\x00" not in fh.read(512):
                        result.append(fpath)
            except OSError:
                pass
        return result


# ── Hashing ───────────────────────────────────────────────────────────────────

def compute_hashes(fpath: str) -> Tuple[str, str, str]:
    """Return (sha256, sha1, md5) hex digests."""
    sha256 = hashlib.sha256()
    sha1   = hashlib.sha1()
    md5    = hashlib.md5()
    with open(fpath, "rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()
