"""
apkshield/reports/json_report.py
"""
import json
from apkshield.models import ScanResult


def generate(result: ScanResult, output_path: str) -> str:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    return output_path
