"""CI gate #2 (invariant #2): users only ever receive their permitted data, no cross-leakage.

Unit layer: domain-tag scoping of the semantic layer, and permission-gated reidentification
(a token never resolves for a user who lacks the field). Integration layer (DB required):
RLS proves two users with different region scopes get disjoint rows, and the read-only role
cannot write.
"""

from __future__ import annotations

import os

import pytest

from app.data import semantic_layer
from app.masking.structured import StructuredTokenMasker
from app.models import MaskCtx, Permissions

# --- unit: domain-tag scoping -----------------------------------------------------------


def test_tables_scoped_to_allowed_tags(analyst_perms):
    names = {t.name for t in semantic_layer.tables_for(analyst_perms)}
    assert names == {"customers", "sales"}  # both are domain_tag="sales"


def test_user_without_tag_sees_no_tables():
    perms = Permissions(
        user_id="x", roles=frozenset({"misc"}), allowed_tags=frozenset({"hr"}),
        row_scopes={"app.user_region": "EMEA"},
    )
    assert semantic_layer.tables_for(perms) == []


# --- unit: reidentification cannot leak across users ------------------------------------


def test_token_never_resolves_for_unauthorized_user(analyst_perms, manager_perms):
    masker = StructuredTokenMasker()
    ctx = MaskCtx(request_id="r", permissions=manager_perms, sensitive_fields=frozenset({"ssn"}))
    masked = masker.mask({"rows": [{"ssn": "111-11-1111"}]}, ctx)
    token_text = masked.payload["rows"][0]["ssn"]

    # Neither analyst nor manager may un-mask ssn -> value must never appear.
    for perms in (analyst_perms, manager_perms):
        out = masker.unmask(token_text, masked.token_map, perms)
        assert "111-11-1111" not in out


# --- integration: RLS isolation + read-only enforcement ---------------------------------


@pytest.mark.integration
def test_rls_isolates_regions_and_role_is_readonly():
    import psycopg

    dsn = os.environ["DATABASE_URL_READONLY"]

    def regions_seen(scope_region: str) -> set[str]:
        with psycopg.connect(dsn) as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                cur.execute("SET TRANSACTION READ ONLY")
                cur.execute("SELECT set_config('app.user_region', %s, true)", (scope_region,))
                cur.execute("SELECT DISTINCT region FROM customers")
                rows = {r[0] for r in cur.fetchall()}
            conn.rollback()
        return rows

    emea = regions_seen("EMEA")
    amer = regions_seen("AMER")
    assert emea == {"EMEA"}
    assert amer == {"AMER"}
    assert emea.isdisjoint(amer)  # zero cross-leakage

    # The read-only role must not be able to write.
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    "INSERT INTO customers (name, region) VALUES ('x', 'EMEA')"
                )
        conn.rollback()


@pytest.mark.integration
def test_readonly_role_cannot_read_withheld_column():
    import psycopg

    dsn = os.environ["DATABASE_URL_READONLY"]
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.user_region', 'EMEA', true)")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute("SELECT internal_notes FROM customers")
        conn.rollback()
