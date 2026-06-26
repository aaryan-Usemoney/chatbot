"""CI gate #3: mask -> unmask restores only permitted fields; tokens deterministic per request."""

from __future__ import annotations

from app.masking.structured import StructuredTokenMasker
from app.models import MaskCtx

ROWS = [
    {"name": "Alice", "email": "alice@example.com", "ssn": "111-11-1111", "region": "EMEA"},
    {"name": "Alice", "email": "alice@example.com", "ssn": "999-99-9999", "region": "EMEA"},
]
SENSITIVE = frozenset({"email", "ssn", "phone"})


def _mask(perms):
    masker = StructuredTokenMasker()
    ctx = MaskCtx(request_id="r1", permissions=perms, sensitive_fields=SENSITIVE)
    masked = masker.mask({"rows": ROWS}, ctx)
    return masker, masked


def test_sensitive_values_are_tokenized(analyst_perms):
    _, masked = _mask(analyst_perms)
    blob = str(masked.payload["rows"])
    assert "alice@example.com" not in blob
    assert "111-11-1111" not in blob
    # non-sensitive columns are untouched
    assert masked.payload["rows"][0]["name"] == "Alice"


def test_tokens_are_deterministic_within_request(analyst_perms):
    _, masked = _mask(analyst_perms)
    r0, r1 = masked.payload["rows"]
    # same email value -> same token across rows
    assert r0["email"] == r1["email"]
    # different ssn values -> different tokens
    assert r0["ssn"] != r1["ssn"]


def test_unmask_is_permission_gated(manager_perms, admin_perms, analyst_perms):
    masker, masked = _mask(admin_perms)
    text = (
        f"email is {masked.payload['rows'][0]['email']} and "
        f"ssn is {masked.payload['rows'][0]['ssn']}"
    )

    # analyst: un-masks nothing -> tokens stay
    out_analyst = masker.unmask(text, masked.token_map, analyst_perms)
    assert "alice@example.com" not in out_analyst
    assert "111-11-1111" not in out_analyst

    # manager: may un-mask email only
    out_manager = masker.unmask(text, masked.token_map, manager_perms)
    assert "alice@example.com" in out_manager
    assert "111-11-1111" not in out_manager  # ssn stays masked

    # admin: may un-mask both
    out_admin = masker.unmask(text, masked.token_map, admin_perms)
    assert "alice@example.com" in out_admin
    assert "111-11-1111" in out_admin


def test_unknown_token_left_intact(analyst_perms):
    masker, masked = _mask(analyst_perms)
    out = masker.unmask("see <EMAIL_99>", masked.token_map, analyst_perms)
    assert "<EMAIL_99>" in out
