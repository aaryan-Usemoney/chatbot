"""Semantic layer — table/column descriptions, domain tags, sensitivity catalogue.

This drives three things:
  * the text-to-SQL prompt (human-readable schema description),
  * which columns the structured masker tokenizes (``sensitive_fields``), and
  * which domain tag each table belongs to (for access scoping / citations).

TODO(human): this describes a demonstration schema (customers, sales). Replace the
``TABLES`` catalogue and ``SENSITIVE_FIELDS`` with the real schema and the agreed
sensitive-field catalogue (BUILD_SPEC section 11). The masking SQL (db/004_masking.sql)
and RLS (db/003_rls.sql) must be kept in sync with this file.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models import Permissions


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    description: str
    sensitive: bool = False


@dataclass(frozen=True)
class Table:
    name: str
    domain_tag: str  # maps to Permissions.allowed_tags
    description: str
    columns: tuple[Column, ...]
    # RLS GUC that scopes rows for this table (set via SET LOCAL per request).
    rls_scope_guc: str | None = None


TABLES: tuple[Table, ...] = (
    Table(
        name="customers",
        domain_tag="sales",
        description="Customer master records.",
        rls_scope_guc="app.user_region",
        columns=(
            Column("id", "bigint", "Surrogate primary key."),
            Column("name", "text", "Customer full name."),
            Column("email", "text", "Contact email.", sensitive=True),
            Column("phone", "text", "Contact phone number.", sensitive=True),
            Column("ssn", "text", "National identifier.", sensitive=True),
            Column("region", "text", "Region the customer belongs to (RLS scope)."),
            # internal_notes is destructively masked at the DB role via anon (db/004),
            # so it never reaches the app in clear form. Excluded from SQL suggestions.
            Column("internal_notes", "text", "Internal free-text notes (DB-masked)."),
        ),
    ),
    Table(
        name="sales",
        domain_tag="sales",
        description="Individual sales transactions.",
        rls_scope_guc="app.user_region",
        columns=(
            Column("id", "bigint", "Surrogate primary key."),
            Column("customer_id", "bigint", "FK to customers.id."),
            Column("amount", "numeric", "Sale amount in account currency."),
            Column("product", "text", "Product name."),
            Column("region", "text", "Region of the sale (RLS scope)."),
            Column("sale_date", "date", "Date of the sale."),
        ),
    ),
)


# Column names treated as sensitive by the app-side masker (reversible tokenization).
SENSITIVE_FIELDS: frozenset[str] = frozenset(
    col.name
    for table in TABLES
    for col in table.columns
    if col.sensitive
)


def tables_for(permissions: Permissions) -> list[Table]:
    """Tables whose domain tag is within the user's allowed tags."""
    return [t for t in TABLES if t.domain_tag in permissions.allowed_tags]


def describe_schema(permissions: Permissions) -> str:
    """Human-readable schema for the text-to-SQL prompt, scoped to allowed domains.

    Note: this description is business context only. It is NOT relied on for access
    control — RLS + the read-only masked role enforce that at the data layer (invariant #2).
    """
    lines: list[str] = []
    for table in tables_for(permissions):
        lines.append(f"TABLE {table.name} -- {table.description}")
        for col in table.columns:
            note = " [sensitive]" if col.sensitive else ""
            lines.append(f"  {col.name} {col.type}{note} -- {col.description}")
        lines.append("")
    return "\n".join(lines).strip()
