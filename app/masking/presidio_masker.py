"""Presidio-based reversible masking for free text (Phase 3).

Stubbed for Phases 1-2. In Phase 3 this implements the ``Masker`` protocol over retrieved
document chunks: Presidio Analyzer detects PII entities, Anonymizer replaces them with
typed tokens, and the entity map is stored in the TokenVault for permission-gated
reidentification. Recognizers are driven by the sensitive-field catalogue (BUILD_SPEC s.11).

TODO(human): wire the real recognizer set from the catalogue before enabling Phase 3.
"""

from __future__ import annotations

from app.models import Masked, MaskCtx, Permissions


class PresidioMasker:
    def mask(self, payload: dict | str, ctx: MaskCtx) -> Masked:  # pragma: no cover - Phase 3
        raise NotImplementedError("PresidioMasker is implemented in Phase 3")

    def unmask(
        self, text: str, token_map: dict, permissions: Permissions
    ) -> str:  # pragma: no cover - Phase 3
        raise NotImplementedError("PresidioMasker is implemented in Phase 3")
