"""Structured masking — reversible tokenization of DB result columns (Phase 2).

This is the app-side masking layer for the structured path. Row visibility is already
enforced by Postgres RLS (invariant #2); this layer handles *column* sensitivity:

  * Columns the semantic layer flags sensitive are replaced with deterministic, typed
    tokens (e.g. ``<EMAIL_1>``) before any prompt is built (invariant #1).
  * The token -> {value, field} map is held in the TokenVault, never in a prompt.
  * ``unmask`` restores a token to its real value ONLY when the requesting user's
    permissions list that field as unmaskable (invariant #6); otherwise the token stays.

Determinism: within one request the same (field, value) pair always yields the same token,
so referential integrity across rows is preserved.

Note on PostgreSQL Anonymizer: ``anon`` is configured (db/004_masking.sql) to destructively
mask columns that NO role may ever see raw — those never reach this layer in clear form.
Columns that some roles may un-mask are intentionally left for this reversible layer.
"""

from __future__ import annotations

import re
from typing import Any

from app.models import Masked, MaskCtx, Permissions

_TOKEN_RE = re.compile(r"<[A-Z0-9_]+_\d+>")


def _token_for(field: str, n: int) -> str:
    return f"<{field.upper()}_{n}>"


class StructuredTokenMasker:
    """Reversible tokenizer for structured result sets."""

    def mask(self, payload: dict | str, ctx: MaskCtx) -> Masked:
        if not isinstance(payload, dict) or "rows" not in payload:
            raise TypeError("StructuredTokenMasker.mask expects {'rows': [...]} payload")

        sensitive = ctx.sensitive_fields
        rows: list[dict[str, Any]] = payload["rows"]

        # value->token cache keyed by field for determinism within the request.
        value_to_token: dict[tuple[str, str], str] = {}
        token_map: dict[str, dict[str, str]] = {}
        counters: dict[str, int] = {}

        masked_rows: list[dict[str, Any]] = []
        for row in rows:
            masked_row: dict[str, Any] = {}
            for col, val in row.items():
                if col in sensitive and val is not None:
                    sval = str(val)
                    key = (col, sval)
                    token = value_to_token.get(key)
                    if token is None:
                        counters[col] = counters.get(col, 0) + 1
                        token = _token_for(col, counters[col])
                        value_to_token[key] = token
                        token_map[token] = {"value": sval, "field": col}
                    masked_row[col] = token
                else:
                    masked_row[col] = val
            masked_rows.append(masked_row)

        return Masked(payload={**payload, "rows": masked_rows}, token_map=token_map)

    def unmask(self, text: str, token_map: dict, permissions: Permissions) -> str:
        def _replace(m: re.Match[str]) -> str:
            token = m.group(0)
            entry = token_map.get(token)
            if entry is None:
                return token  # unknown token: leave as-is
            if permissions.may_unmask(entry["field"]):
                return entry["value"]
            return token  # not authorized for this field -> stays masked (invariant #6)

        return _TOKEN_RE.sub(_replace, text)
