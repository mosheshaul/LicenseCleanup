"""Logging setup with secret redaction.

Every log record passes through :class:`SecretRedactingFilter`, which masks
any registered secret value and common credential patterns before the record
is written. This is a defence-in-depth measure: the code never logs secrets
intentionally, but exception messages from third-party libraries could.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

REDACTED = "***REDACTED***"

_PATTERNS = [
    re.compile(r"(?i)(x-api-key|authorization|x-customer-code)(['\"]?\s*[:=]\s*['\"]?)([^'\",\s}]+)"),
    re.compile(r"(?i)(password|passwd|pwd|token|secret)(['\"]?\s*[:=]\s*['\"]?)([^'\",\s}]+)"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
]

_secret_values: set[str] = set()


def register_secret(value: str | None) -> None:
    """Register a secret value so it is masked in all subsequent log output."""
    if value and len(value) >= 4:
        _secret_values.add(value)


def redact(text: str) -> str:
    """Return ``text`` with registered secrets and credential patterns masked."""
    for secret in sorted(_secret_values, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts secrets from the fully formatted message."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = redact(message)
        record.args = None
        if record.exc_info and record.exc_info[1] is not None:
            # Render the exception now so the traceback text is redacted too.
            formatter = logging.Formatter()
            record.exc_text = redact(formatter.formatException(record.exc_info))
            record.exc_info = None
        return True


def setup_logging(level: str = "INFO", log_dir: str | Path | None = None, execution_id: str = "") -> None:
    """Configure root logging to stderr (and optionally a log file)."""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s [%(name)s] " + (f"[{execution_id}] " if execution_id else "") + "%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    redactor = SecretRedactingFilter()

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    stream.addFilter(redactor)
    root.addHandler(stream)

    if log_dir:
        path = Path(log_dir)
        path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path / f"license-cleanup-{execution_id or 'run'}.log", encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler.addFilter(redactor)
        root.addHandler(file_handler)

    # Third-party libraries can be chatty and may echo request details at DEBUG.
    for noisy in ("urllib3", "ldap3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
