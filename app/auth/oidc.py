"""OIDC token validation.

Validates a bearer JWT and returns the verified claims. Two modes:

  * Production / staging: RS256 verified against the IdP's JWKS, with issuer and
    audience checks. This is the only path that should run in deployed envs.
  * Dev mode (AUTH_DEV_MODE=true, non-prod only): a symmetric HS256 token signed with
    AUTH_DEV_HS256_SECRET is accepted so the stack can run without a real IdP. This path
    refuses to activate when APP_ENV is production.

We never log token contents (invariant #7).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient

from app.config import Settings, get_settings


class AuthError(Exception):
    """Raised when a token is missing, malformed, expired, or fails verification."""


@lru_cache
def _jwks_client(jwks_url: str) -> PyJWKClient:
    # PyJWKClient caches signing keys internally.
    return PyJWKClient(jwks_url)


def _verify_rs256(token: str, settings: Settings) -> dict[str, Any]:
    if not settings.oidc_jwks_url:
        raise AuthError("OIDC is not configured (missing OIDC_JWKS_URL)")
    try:
        signing_key = _jwks_client(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.oidc_audience or None,
            issuer=settings.oidc_issuer or None,
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError as exc:
        # Message is generic on purpose; do not echo token material.
        raise AuthError("token verification failed") from exc


def _verify_dev_hs256(token: str, settings: Settings) -> dict[str, Any]:
    if settings.is_production:
        raise AuthError("dev auth mode is disabled in production")
    secret = settings.auth_dev_hs256_secret.get_secret_value()
    if not secret:
        raise AuthError("dev auth secret not configured")
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience=settings.oidc_audience or None,
            options={"require": ["sub"], "verify_aud": bool(settings.oidc_audience)},
        )
    except jwt.PyJWTError as exc:
        raise AuthError("token verification failed") from exc


def verify_token(token: str, settings: Settings | None = None) -> dict[str, Any]:
    """Verify a bearer JWT and return its claims, or raise ``AuthError``."""
    settings = settings or get_settings()
    if not token:
        raise AuthError("missing bearer token")

    # Prefer real OIDC; fall back to dev HS256 only when explicitly enabled and non-prod.
    if settings.oidc_jwks_url:
        return _verify_rs256(token, settings)
    if settings.auth_dev_mode:
        return _verify_dev_hs256(token, settings)
    raise AuthError("no auth method configured")
