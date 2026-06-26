"""Database access with a strict separation of roles.

Two pools:
  * ``owner_pool``     — DATABASE_URL. Used ONLY for audit writes and ingestion. Never
                         executes model-generated SQL.
  * ``readonly_pool``  — DATABASE_URL_READONLY. The masked, read-only role (invariant #8).
                         ALL generated queries run here, inside a READ ONLY transaction
                         with per-request RLS scopes applied via SET LOCAL (invariant #2).

Defense in depth on invariant #8: even though the role is read-only at the DB level
(db/005_roles.sql), every generated query also runs in an explicitly READ ONLY transaction.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from app.config import get_settings
from app.models import Permissions

_owner_pool: AsyncConnectionPool | None = None
_readonly_pool: AsyncConnectionPool | None = None


async def init_pools() -> None:
    global _owner_pool, _readonly_pool
    settings = get_settings()
    if _owner_pool is None:
        _owner_pool = AsyncConnectionPool(
            settings.database_url.get_secret_value(), open=False, max_size=5
        )
        await _owner_pool.open(wait=True)
    if _readonly_pool is None:
        _readonly_pool = AsyncConnectionPool(
            settings.database_url_readonly.get_secret_value(), open=False, max_size=5
        )
        await _readonly_pool.open(wait=True)


async def close_pools() -> None:
    global _owner_pool, _readonly_pool
    if _owner_pool is not None:
        await _owner_pool.close()
        _owner_pool = None
    if _readonly_pool is not None:
        await _readonly_pool.close()
        _readonly_pool = None


def _require(pool: AsyncConnectionPool | None, name: str) -> AsyncConnectionPool:
    if pool is None:
        raise RuntimeError(f"{name} not initialized; call init_pools() at startup")
    return pool


# --- Owner pool (audit / ingestion only) ------------------------------------------------


@asynccontextmanager
async def owner_conn() -> AsyncIterator[Any]:
    pool = _require(_owner_pool, "owner_pool")
    async with pool.connection() as conn:
        yield conn


# --- Read-only masked pool (generated-query execution) ----------------------------------

# Only these GUCs may be SET LOCAL from resolved permissions. This prevents a crafted
# scope key from touching unrelated settings.
_ALLOWED_SCOPE_GUCS = frozenset({"app.user_region", "app.user_department"})


async def run_readonly_query(
    sql: str,
    permissions: Permissions,
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute a validated read-only SELECT under the masked role.

    The query runs in a READ ONLY transaction with the user's RLS scopes applied via
    SET LOCAL, so PostgreSQL — not the prompt — enforces row visibility (invariant #2).

    ``sql`` MUST already have passed app.nodes.sql_tool.validate_sql.
    """
    pool = _require(_readonly_pool, "readonly_pool")
    async with pool.connection() as conn:
        # autocommit off so the transaction (and its SET LOCAL scopes) is real.
        await conn.set_autocommit(False)
        async with conn.cursor(row_factory=dict_row) as cur:
            # Belt-and-suspenders read-only enforcement (invariant #8).
            await cur.execute("SET TRANSACTION READ ONLY")
            for guc, value in permissions.row_scopes.items():
                if guc not in _ALLOWED_SCOPE_GUCS:
                    raise ValueError(f"refusing to set unknown scope GUC: {guc}")
                # SET LOCAL cannot be parameterized; set_config(..., is_local=true) can.
                await cur.execute(
                    "SELECT set_config(%s, %s, true)", (guc, value)
                )
            await cur.execute(sql, params or {})
            rows = await cur.fetchall()
        await conn.rollback()  # read-only: nothing to commit
        return rows
