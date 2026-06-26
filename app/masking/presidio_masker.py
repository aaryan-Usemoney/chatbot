"""Reversible PII masking for free text (Phase 3).

Detects PII spans (via a ``PiiDetector`` — Presidio by default) in retrieved document chunks
and replaces each span with a deterministic, typed token (``<EMAIL_1>`` ...) via the shared
token core, before any chunk reaches the LLM (invariant #1). The token map is held in the
TokenVault and reidentification is permission-gated (invariant #6), reusing the exact
``unmask`` used by the structured path.

The detector is injectable: production uses ``PresidioDetector`` (Presidio + spaCy, lazy
imported); tests and lightweight deployments can pass ``RegexPiiDetector`` to avoid the NLP
stack. The detected-entity -> field mapping lives in app/masking/pii_detect.py and should be
driven by the sensitive-field catalogue (BUILD_SPEC section 11). TODO(human).
"""

from __future__ import annotations

from typing import Any

from app.masking.pii_detect import PiiDetector, PresidioDetector
from app.masking.tokens import TokenAllocator, mask_text_spans, unmask_text
from app.models import Masked, MaskCtx, Permissions


class PresidioMasker:
    def __init__(self, detector: PiiDetector | None = None) -> None:
        # Default detector is Presidio; constructing it is cheap (analyzer is lazy).
        self._detector: PiiDetector = detector or PresidioDetector()

    def mask(self, payload: dict | str, ctx: MaskCtx) -> Masked:  # noqa: ARG002
        alloc = TokenAllocator()

        if isinstance(payload, str):
            masked = mask_text_spans(payload, self._detector.detect(payload), alloc)
            return Masked(payload=masked, token_map=alloc.token_map)

        if isinstance(payload, dict) and "chunks" in payload:
            masked_chunks: list[dict[str, Any]] = []
            for chunk in payload["chunks"]:
                content = chunk.get("content", "")
                masked_content = mask_text_spans(
                    content, self._detector.detect(content), alloc
                )
                masked_chunks.append({**chunk, "content": masked_content})
            return Masked(
                payload={**payload, "chunks": masked_chunks}, token_map=alloc.token_map
            )

        raise TypeError("PresidioMasker.mask expects a str or {'chunks': [...]} payload")

    def unmask(self, text: str, token_map: dict, permissions: Permissions) -> str:
        return unmask_text(text, token_map, permissions)
