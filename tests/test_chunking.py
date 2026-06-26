"""Phase 3: document chunking behavior."""

from __future__ import annotations

from app.data.ingest import chunk_text


def test_empty_text_yields_no_chunks():
    assert chunk_text("") == []
    assert chunk_text("   ") == []


def test_short_text_is_single_chunk():
    assert chunk_text("hello world", chunk_chars=1000) == ["hello world"]


def test_long_text_is_split_with_overlap():
    text = "abcdefghij" * 50  # 500 chars
    chunks = chunk_text(text, chunk_chars=100, overlap=20)
    assert len(chunks) > 1
    # every chunk is within the size bound
    assert all(len(c) <= 100 for c in chunks)
    # overlap: the tail of chunk 0 reappears at the head of chunk 1
    assert chunks[0][-20:] == chunks[1][:20]
    # reassembling with the step reconstructs the original prefix
    assert text.startswith(chunks[0])
