"""Document ingestion — chunk + embed (local) + index with access_tags (Phase 3).

  * Chunks documents with a simple character window + overlap.
  * Embeds each chunk with the self-hosted model (invariant #4: text never leaves the
    boundary for embedding).
  * Writes rows to doc_chunks with ``access_tags`` (the metadata used to enforce per-user
    visibility at retrieval, invariant #2) via the OWNER pool (the read-only role cannot write).

Policy decision: chunk ``content`` is stored ORIGINAL (not pre-masked). Masking happens at
retrieval time (reversibly, via Presidio) so authorized users can be shown real values
(invariant #6). The store itself is inside the trust boundary; only the LLM egress is not.
TODO(human): if policy requires masked-at-rest storage, mask before insert and drop the
retrieval-time mask.

Embeddings are written as a pgvector literal cast (``%s::vector``) so no extra psycopg
adapter is required.
"""

from __future__ import annotations

import json
from typing import Any

from app.data import embeddings
from app.data.db import owner_conn

DEFAULT_CHUNK_CHARS = 1000
DEFAULT_OVERLAP_CHARS = 150


def chunk_text(
    text: str,
    chunk_chars: int = DEFAULT_CHUNK_CHARS,
    overlap: int = DEFAULT_OVERLAP_CHARS,
) -> list[str]:
    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= chunk_chars:
        return [text]
    step = max(1, chunk_chars - overlap)
    chunks: list[str] = []
    for start in range(0, len(text), step):
        piece = text[start : start + chunk_chars].strip()
        if piece:
            chunks.append(piece)
        if start + chunk_chars >= len(text):
            break
    return chunks


def _to_vector_literal(vec: list[float]) -> str:
    return "[" + ",".join(f"{x:.8f}" for x in vec) + "]"


async def ingest_document(
    *,
    document_id: str,
    text: str,
    access_tags: list[str],
    metadata: dict[str, Any] | None = None,
) -> int:
    """Chunk, embed (locally), and index a document. Returns the number of chunks written."""
    if not access_tags:
        raise ValueError("access_tags is required (invariant #2): a chunk with no tags is unreachable")

    chunks = chunk_text(text)
    if not chunks:
        return 0

    vectors = embeddings.embed_texts(chunks)  # local model only (invariant #4)

    async with owner_conn() as conn:
        async with conn.cursor() as cur:
            for idx, (content, vec) in enumerate(zip(chunks, vectors)):
                meta = {**(metadata or {}), "chunk_index": idx}
                await cur.execute(
                    """
                    INSERT INTO doc_chunks (document_id, content, embedding, access_tags, metadata)
                    VALUES (%s, %s, %s::vector, %s, %s)
                    """,
                    (document_id, content, _to_vector_literal(vec), access_tags, json.dumps(meta)),
                )
        await conn.commit()
    return len(chunks)
