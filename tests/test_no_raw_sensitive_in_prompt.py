"""CI gate #1 (invariant #1): no raw sensitive value reaches the LLM client.

We exercise the real mask -> synthesize path with a fake Groq transport that captures the
exact messages that would have been sent, and assert no seeded raw value appears in them.
We also assert the client-side guard hard-fails (raises) if a raw value ever survives.
"""

from __future__ import annotations

import json

import pytest

from app.llm import groq_client
from app.llm.groq_client import RawSensitiveLeak, assert_contains_no_raw_sensitive
from app.masking.pii_detect import RegexPiiDetector
from app.masking.presidio_masker import PresidioMasker
from app.nodes.mask import mask_structured, mask_unstructured
from app.nodes.synthesize import synthesize_answer, synthesize_answer_from_chunks

SEEDED = {"email": "alice@example.com", "ssn": "111-11-1111", "phone": "555-0101"}


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChoice(content)]


class _FakeCompletions:
    def __init__(self, sink: dict) -> None:
        self._sink = sink

    def create(self, *, model, messages, **kwargs):  # noqa: ARG002
        self._sink["messages"] = messages
        return _FakeResponse("ok (masked tokens preserved)")


class _FakeChat:
    def __init__(self, sink: dict) -> None:
        self.completions = _FakeCompletions(sink)


class _FakeClient:
    def __init__(self, sink: dict) -> None:
        self.chat = _FakeChat(sink)


@pytest.fixture
def captured(monkeypatch):
    sink: dict = {}
    monkeypatch.setattr(groq_client, "_client", _FakeClient(sink))
    return sink


def test_masked_prompt_contains_no_raw_sensitive(captured, manager_perms, vault):
    raw_result = {
        "rows": [{"name": "Alice", **SEEDED, "region": "EMEA"}],
        "sources": [{"kind": "table", "ref": "customers"}],
    }
    masked_result, forbidden = mask_structured(
        request_id="req1", result=raw_result, permissions=manager_perms, vault=vault
    )
    # all seeded sensitive values were captured as forbidden
    assert set(SEEDED.values()) <= set(forbidden)

    answer = synthesize_answer("Who is the customer?", masked_result, forbidden_values=forbidden)
    assert answer  # fake transport returned something

    blob = json.dumps(captured["messages"])
    for raw_value in SEEDED.values():
        assert raw_value not in blob, f"raw value leaked into prompt: {raw_value!r}"


def test_masked_doc_prompt_contains_no_raw_pii(captured, manager_perms, vault):
    raw_result = {
        "chunks": [
            {
                "id": 1,
                "document_id": "doc1",
                "content": (
                    "Contact Alice at alice@example.com or 555-123-4567. "
                    "Her SSN is 111-11-1111."
                ),
            }
        ],
        "sources": [{"kind": "document", "ref": "doc1"}],
    }
    masker = PresidioMasker(detector=RegexPiiDetector())
    masked_result, forbidden = mask_unstructured(
        request_id="reqdoc", result=raw_result, permissions=manager_perms,
        vault=vault, masker=masker,
    )
    assert {"alice@example.com", "555-123-4567", "111-11-1111"} <= set(forbidden)

    answer = synthesize_answer_from_chunks(
        "Who do I contact?", masked_result, forbidden_values=forbidden
    )
    assert answer

    blob = json.dumps(captured["messages"])
    for raw_value in ("alice@example.com", "555-123-4567", "111-11-1111"):
        assert raw_value not in blob, f"raw PII leaked into prompt: {raw_value!r}"


def test_guard_raises_on_raw_value():
    with pytest.raises(RawSensitiveLeak):
        assert_contains_no_raw_sensitive(
            "the email is alice@example.com", ["alice@example.com"]
        )


def test_synthesize_aborts_before_egress_if_masking_failed(captured):
    # Simulate a masking failure: a raw value is still present but listed as forbidden.
    leaky_result = {"rows": [{"email": "alice@example.com"}], "sources": []}
    with pytest.raises(RawSensitiveLeak):
        synthesize_answer(
            "q", leaky_result, forbidden_values=["alice@example.com"]
        )
    # The fake transport must never have been called.
    assert "messages" not in captured
