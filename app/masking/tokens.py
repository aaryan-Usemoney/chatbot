"""Shared tokenization core for all maskers.

Both the structured masker (column values) and the Presidio masker (free-text PII) produce
the SAME token shape (``<FIELD_n>``) and the SAME ``token_map`` schema
(``{token: {"value": <raw>, "field": <field>}}``), so reidentification (invariant #6) is a
single, audited implementation regardless of source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import Permissions

TOKEN_RE = re.compile(r"<[A-Z0-9_]+_\d+>")


def token_for(field: str, n: int) -> str:
    return f"<{field.upper()}_{n}>"


@dataclass(frozen=True)
class Span:
    """A detected sensitive span in a text: [start, end) carrying a logical field name."""

    start: int
    end: int
    field: str


class TokenAllocator:
    """Allocates deterministic tokens within a single request.

    The same (field, value) pair always maps to the same token, preserving referential
    integrity across rows/chunks. Holds the growing ``token_map`` for the request.
    """

    def __init__(self) -> None:
        self._value_to_token: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        self.token_map: dict[str, dict[str, str]] = {}

    def token(self, field: str, value: str) -> str:
        key = (field, value)
        existing = self._value_to_token.get(key)
        if existing is not None:
            return existing
        self._counters[field] = self._counters.get(field, 0) + 1
        tok = token_for(field, self._counters[field])
        self._value_to_token[key] = tok
        self.token_map[tok] = {"value": value, "field": field}
        return tok


def mask_text_spans(text: str, spans: list[Span], allocator: TokenAllocator) -> str:
    """Replace each span in ``text`` with a deterministic token via ``allocator``.

    Overlapping spans are resolved by keeping the earliest, longest span. Replacement is
    done right-to-left so earlier offsets stay valid.
    """
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    chosen: list[Span] = []
    last_end = -1
    for sp in ordered:
        if sp.start >= last_end:
            chosen.append(sp)
            last_end = sp.end
    out = text
    for sp in sorted(chosen, key=lambda s: s.start, reverse=True):
        value = text[sp.start : sp.end]
        tok = allocator.token(sp.field, value)
        out = out[: sp.start] + tok + out[sp.end :]
    return out


def unmask_text(text: str, token_map: dict, permissions: Permissions) -> str:
    """Restore tokens to real values only for fields the user may see (invariant #6)."""

    def _replace(m: re.Match[str]) -> str:
        token = m.group(0)
        entry = token_map.get(token)
        if entry is None:
            return token  # unknown token: leave as-is
        if permissions.may_unmask(entry["field"]):
            return entry["value"]
        return token  # not authorized -> stays masked

    return TOKEN_RE.sub(_replace, text)
