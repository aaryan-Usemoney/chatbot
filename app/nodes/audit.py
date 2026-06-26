"""Audit node — one row per request, always.

The audit row records WHO asked, WHAT (masked) question, WHICH sources were touched, and
the final decision (answered | refused + reason). The question is stored already-masked
when it may contain PII (BUILD_SPEC section 5); callers pass the masked form.

Writes use the owner pool (the read-only role cannot INSERT).
"""

from __future__ import annotations

import json
from typing import Any

from app.data.db import owner_conn
from app.observability import get_logger

log = get_logger(__name__)


async def write_audit(
    *,
    user_id: str,
    masked_question: str | None,
    sources: list[dict[str, Any]] | None,
    decision: str,
) -> int:
    """Insert an audit row and return its id."""
    async with owner_conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO audit_log (user_id, question, sources, decision)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user_id,
                    masked_question,
                    json.dumps(sources or []),
                    decision,
                ),
            )
            row = await cur.fetchone()
        await conn.commit()
    audit_id = int(row[0]) if row else -1
    # Log the decision and id only — never the question content.
    log.info("audit user=%s decision=%s id=%s", user_id, decision, audit_id)
    return audit_id
