"""Shared test configuration.

Env is set BEFORE any app import so pydantic Settings pick up test values. Most tests are
pure unit tests (no DB/Redis/network). Tests that need the live stack are marked
``@pytest.mark.integration`` and skipped unless RUN_INTEGRATION=1.
"""

from __future__ import annotations

import os

# --- test environment (must precede app imports) ----------------------------------------
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("AUTH_DEV_MODE", "true")
os.environ.setdefault("AUTH_DEV_HS256_SECRET", "test-secret-at-least-32-bytes-long-xx")
os.environ.setdefault("OIDC_JWKS_URL", "")  # force dev auth path
os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("GROQ_ZDR_CONFIRMED", "true")
os.environ.setdefault("DATABASE_URL", "postgresql://chatbot_owner:owner_pw@localhost:5432/chatbot")
os.environ.setdefault(
    "DATABASE_URL_READONLY", "postgresql://chatbot_readonly:readonly_pw@localhost:5432/chatbot"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

import pytest  # noqa: E402

from app.masking.vault_redis import InMemoryTokenVault  # noqa: E402
from app.models import Permissions  # noqa: E402


def _perms(roles, tags, unmask, region="EMEA") -> Permissions:
    return Permissions(
        user_id="u-" + "-".join(sorted(roles)),
        roles=frozenset(roles),
        allowed_tags=frozenset(tags),
        row_scopes={"app.user_region": region},
        unmaskable_fields=frozenset(unmask),
    )


@pytest.fixture
def analyst_perms() -> Permissions:
    return _perms({"analyst"}, {"sales", "marketing"}, set())


@pytest.fixture
def manager_perms() -> Permissions:
    return _perms({"manager"}, {"sales", "marketing", "hr"}, {"email"})


@pytest.fixture
def admin_perms() -> Permissions:
    return _perms({"admin"}, {"sales", "marketing", "hr", "finance"}, {"email", "phone", "ssn"})


@pytest.fixture
def vault() -> InMemoryTokenVault:
    return InMemoryTokenVault()


def pytest_collection_modifyitems(config, items):
    if os.environ.get("RUN_INTEGRATION") == "1":
        return
    skip = pytest.mark.skip(reason="integration test; set RUN_INTEGRATION=1 with stack up")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)
