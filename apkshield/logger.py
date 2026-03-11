"""
apkshield/logger.py
Centralised logger — call setup() once from the CLI entry point.
"""
import logging
from typing import Optional

_FMT = "[%(asctime)s] [%(levelname)-8s] %(message)s"
_DATE = "%H:%M:%S"


def setup(log_file: Optional[str] = None, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("APKShield")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(_FMT, _DATE))
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(_FMT, _DATE))
        logger.addHandler(fh)

    return logger


def get() -> logging.Logger:
    return logging.getLogger("APKShield")
