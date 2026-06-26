"""Document ingestion — chunk + embed + index (Phase 3).

Stubbed for Phases 1-2. In Phase 3 this:
  * chunks documents,
  * embeds each chunk with a self-hosted sentence-transformers model (invariant #4: text
    never leaves the boundary for embedding),
  * writes rows to doc_chunks with ``access_tags`` for metadata filtering (invariant #2).

TODO(human): confirm chunking strategy and the access_tags source before enabling.
"""

from __future__ import annotations


def ingest_document(*args, **kwargs):  # pragma: no cover - Phase 3
    raise NotImplementedError("Document ingestion is implemented in Phase 3")
