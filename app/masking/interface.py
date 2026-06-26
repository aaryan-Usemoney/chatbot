"""Masking contracts (BUILD_SPEC section 6).

The ``Masker`` protocol is the single seam through which sensitive values become tokens
and (selectively) come back. Two implementations:
  * StructuredTokenMasker (app/masking/structured.py) — Phase 2, reversible tokenization
    of DB result columns flagged sensitive by the semantic layer.
  * PresidioMasker (app/masking/presidio_masker.py) — Phase 3, reversible PII masking of
    free text retrieved from documents.

The ``TokenVault`` holds token maps out-of-band (Redis, short TTL). A token map is NEVER
placed in an LLM prompt (invariant #1) and is permission-gated on the way back (invariant #6).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.models import Masked, MaskCtx, Permissions


@runtime_checkable
class Masker(Protocol):
    def mask(self, payload: dict | str, ctx: MaskCtx) -> Masked:
        """Replace sensitive values with deterministic, referential tokens.

        Same real value -> same token within a single request (``ctx.request_id``).
        """
        ...

    def unmask(self, text: str, token_map: dict, permissions: Permissions) -> str:
        """Restore tokens to real values ONLY for fields the user may see; leave others masked."""
        ...


@runtime_checkable
class TokenVault(Protocol):
    def put(self, request_id: str, token_map: dict) -> None: ...

    def get(self, request_id: str) -> dict: ...
