"""The dev-only token endpoint mints usable tokens and is hard-gated off in production."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.main as main
from app.auth.oidc import verify_token
from app.auth.permissions import resolve_permissions, user_from_claims
from app.main import DevTokenRequest, dev_token


async def test_dev_token_mints_usable_token():
    out = await dev_token(DevTokenRequest(sub="u", roles=["manager"], region="EMEA"))
    claims = verify_token(out["token"])
    perms = resolve_permissions(user_from_claims(claims))
    assert perms.user_id == "u"
    assert perms.row_scopes["app.user_region"] == "EMEA"
    assert perms.may_unmask("email") is True
    assert perms.may_unmask("ssn") is False


async def test_dev_token_blocked_in_production(monkeypatch):
    class _Prod:
        is_production = True
        auth_dev_mode = True

    monkeypatch.setattr(main, "get_settings", lambda: _Prod())
    with pytest.raises(HTTPException) as exc:
        await dev_token(DevTokenRequest())
    assert exc.value.status_code == 404
