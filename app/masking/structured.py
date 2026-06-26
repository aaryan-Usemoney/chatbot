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

from typing import Any

from app.masking.tokens import TokenAllocator, unmask_text
from app.models import Masked, MaskCtx, Permissions


class StructuredTokenMasker:
    """Reversible tokenizer for structured result sets."""

    def mask(self, payload: dict | str, ctx: MaskCtx) -> Masked:
        if not isinstance(payload, dict) or "rows" not in payload:
            raise TypeError("StructuredTokenMasker.mask expects {'rows': [...]} payload")

        sensitive = ctx.sensitive_fields
        rows: list[dict[str, Any]] = payload["rows"]
        alloc = TokenAllocator()

        masked_rows: list[dict[str, Any]] = []
        for row in rows:
            masked_row: dict[str, Any] = {}
            for col, val in row.items():
                if col in sensitive and val is not None:
                    masked_row[col] = alloc.token(col, str(val))
                else:
                    masked_row[col] = val
            masked_rows.append(masked_row)

        return Masked(payload={**payload, "rows": masked_rows}, token_map=alloc.token_map)

    def unmask(self, text: str, token_map: dict, permissions: Permissions) -> str:
        return unmask_text(text, token_map, permissions)
