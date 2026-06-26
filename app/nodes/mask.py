"""Mask node — the left slice of the masking sandwich.

Takes a raw result set, replaces sensitive values with tokens, persists the token map in the
TokenVault (never in a prompt), and returns the masked payload plus the set of raw values
that must NOT appear downstream (fed to the LLM guard).

  * Structured path -> StructuredTokenMasker over result columns.
  * Unstructured path -> PresidioMasker over retrieved chunk text.

Both produce the same token_map schema, so reidentification is uniform (invariant #6).
"""

from __future__ import annotations

from typing import Any

from app.data.semantic_layer import SENSITIVE_FIELDS
from app.masking.interface import Masker, TokenVault
from app.masking.presidio_masker import PresidioMasker
from app.masking.structured import StructuredTokenMasker
from app.models import MaskCtx, Permissions

_masker = StructuredTokenMasker()
_doc_masker: Masker = PresidioMasker()


def mask_structured(
    *,
    request_id: str,
    result: dict[str, Any],
    permissions: Permissions,
    vault: TokenVault,
) -> tuple[dict[str, Any], list[str]]:
    """Mask a structured result and stash its token map. Returns (masked_result, forbidden_values)."""
    ctx = MaskCtx(
        request_id=request_id,
        permissions=permissions,
        sensitive_fields=SENSITIVE_FIELDS,
    )
    masked = _masker.mask({"rows": result["rows"]}, ctx)
    vault.put(request_id, masked.token_map)

    forbidden = [entry["value"] for entry in masked.token_map.values()]
    masked_result = {**result, "rows": masked.payload["rows"]}
    return masked_result, forbidden


def mask_unstructured(
    *,
    request_id: str,
    result: dict[str, Any],
    permissions: Permissions,
    vault: TokenVault,
    masker: Masker | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Mask retrieved chunk text (Presidio) and stash its token map.

    Returns (masked_result, forbidden_values). ``masker`` is injectable for testing.
    """
    masker = masker or _doc_masker
    ctx = MaskCtx(request_id=request_id, permissions=permissions)
    masked = masker.mask({"chunks": result["chunks"]}, ctx)
    vault.put(request_id, masked.token_map)

    forbidden = [entry["value"] for entry in masked.token_map.values()]
    masked_result = {**result, "chunks": masked.payload["chunks"]}
    return masked_result, forbidden
