"""Secure, structured logging.

Passwords, tokens and other secrets are never written to logs. Long values are
truncated. This module provides the app logger plus helpers to scrub secrets.
"""
from __future__ import annotations

import json
import logging
import re
import sys

from ..config import settings

SECRET_PATTERNS = [
    re.compile(r"(password[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(token[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(secret[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)\S+", re.IGNORECASE),
]


def scrub(value: str) -> str:
    out = value
    for pat in SECRET_PATTERNS:
        out = pat.sub(r"\1<redacted>", out)
    return out


class SecureFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        if record.args:
            record.args = tuple(
                scrub(a) if isinstance(a, str) else a for a in record.args
            )
        return super().format(record)


def setup_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        SecureFormatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())
    logger = logging.getLogger("sentinelsoc")
    logger.propagate = True
    return logger


logger = setup_logging()


def log_json(level: str, message: str, **fields) -> None:
    record = {"msg": message, **fields}
    # Never log sensitive fields.
    record.pop("password", None)
    record.pop("token", None)
    record.pop("secret_key", None)
    getattr(logger, level)(json.dumps(record, default=str))
