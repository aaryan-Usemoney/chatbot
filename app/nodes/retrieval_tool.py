"""Vector retrieval node (Phase 3).

Stubbed for Phases 1-2. In Phase 3: embed the query with the local model, run a pgvector
similarity search filtered by ``access_tags && :user_allowed_tags`` (invariant #2), then
Presidio-mask the retrieved chunks before they reach synthesis (invariant #1).
"""

from __future__ import annotations

from app.models import Permissions


async def run_retrieval_path(question: str, permissions: Permissions):  # pragma: no cover
    raise NotImplementedError("Vector retrieval is implemented in Phase 3")
