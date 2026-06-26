"""Reidentify node — the right slice of the masking sandwich (invariant #6).

After synthesis returns text containing tokens, restore each token to its real value ONLY
for fields the requesting user is authorized to see. Tokens for unauthorized fields stay
masked. The token map is pulled from the TokenVault (never from the prompt).
"""

from __future__ import annotations

from app.masking.interface import TokenVault
from app.masking.structured import StructuredTokenMasker
from app.models import Permissions

_masker = StructuredTokenMasker()


def reidentify(
    *,
    request_id: str,
    text: str,
    permissions: Permissions,
    vault: TokenVault,
) -> str:
    token_map = vault.get(request_id)
    if not token_map:
        return text
    return _masker.unmask(text, token_map, permissions)
