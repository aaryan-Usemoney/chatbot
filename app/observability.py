"""Logging that is safe by construction.

Invariant #7: never log secrets or raw sensitive data. We expose a plain logger and a
``safe`` helper that callers use to scrub obvious secret-shaped material. The real
guarantee comes from discipline at call sites (we log ids and decisions, not payloads),
but ``redact`` catches accidental bearer tokens / long hex secrets.
"""

from __future__ import annotations

import logging
import re

from app.config import get_settings

_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
_LONG_SECRET = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def redact(text: str) -> str:
    text = _BEARER.sub("Bearer <redacted>", text)
    text = _LONG_SECRET.sub("<redacted>", text)
    return text


_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        logging.basicConfig(
            level=get_settings().log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        _configured = True
    return logging.getLogger(name)
