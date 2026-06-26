"""Vector retrieval node (Phase 3).

Embeds the query with the local model (invariant #4), runs a pgvector similarity search
filtered by ``access_tags`` against the user's allowed tags (invariant #2), and returns the
retrieved chunks plus citations. The caller MUST pass the chunk text through the masker
before any synthesis prompt is built (invariant #1).
"""

from __future__ import annotations

from typing import Any

from app.data import embeddings
from app.data.db import run_readonly_vector_search
from app.models import Permissions

DEFAULT_K = 5


async def run_retrieval_path(
    question: str, permissions: Permissions, *, k: int = DEFAULT_K
) -> dict[str, Any]:
    query_vec = embeddings.embed_query(question)
    chunks = await run_readonly_vector_search(query_vec, permissions, k=k)

    # Distinct documents touched -> citations / audit sources.
    seen: list[str] = []
    for c in chunks:
        if c["document_id"] not in seen:
            seen.append(c["document_id"])

    return {
        "chunks": [
            {
                "id": c["id"],
                "document_id": c["document_id"],
                "content": c["content"],
                "similarity": c.get("similarity"),
            }
            for c in chunks
        ],
        "sources": [{"kind": "document", "ref": doc_id} for doc_id in seen],
    }
