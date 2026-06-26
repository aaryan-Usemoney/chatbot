"""Phase 1 auth: dev JWT verification + claim->permission resolution; bad tokens rejected."""

from __future__ import annotations

import jwt
import pytest

from app.auth.oidc import AuthError, verify_token
from app.auth.permissions import (
    PermissionError_,
    resolve_permissions,
    user_from_claims,
)
from app.config import get_settings

SECRET = "test-secret-at-least-32-bytes-long-xx"  # matches conftest AUTH_DEV_HS256_SECRET


def _token(claims: dict) -> str:
    return jwt.encode(claims, SECRET, algorithm="HS256")


def test_valid_dev_token_resolves_permissions():
    token = _token({"sub": "alice", "roles": ["manager"], "region": "EMEA"})
    claims = verify_token(token, get_settings())
    user = user_from_claims(claims)
    perms = resolve_permissions(user)

    assert perms.user_id == "alice"
    assert "manager" in perms.roles
    assert perms.row_scopes["app.user_region"] == "EMEA"
    assert "hr" in perms.allowed_tags
    assert perms.may_unmask("email") is True
    assert perms.may_unmask("ssn") is False


def test_missing_token_rejected():
    with pytest.raises(AuthError):
        verify_token("", get_settings())


def test_tampered_token_rejected():
    token = _token({"sub": "alice", "roles": ["manager"]})
    with pytest.raises(AuthError):
        verify_token(token + "x", get_settings())


def test_principal_without_roles_is_refused():
    token = _token({"sub": "nobody"})
    user = user_from_claims(verify_token(token, get_settings()))
    with pytest.raises(PermissionError_):
        resolve_permissions(user)
