"""Phase 5: optional LLM-judge groundedness — verdict parsing + masked-only egress."""

from __future__ import annotations

import pytest

from app.llm import groq_client
from app.llm.groq_client import RawSensitiveLeak
from app.nodes.groundedness import judge_groundedness


class _FakeClient:
    def __init__(self, content: str) -> None:
        c = content

        class _Completions:
            def create(self, *, model, messages, **kwargs):  # noqa: ARG002
                class _M:
                    content = c

                class _Ch:
                    message = _M()

                class _R:
                    choices = [_Ch()]

                return _R()

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


def test_judge_yes(monkeypatch):
    monkeypatch.setattr(groq_client, "_client", _FakeClient("YES"))
    assert judge_groundedness("masked answer", "masked context") is True


def test_judge_no(monkeypatch):
    monkeypatch.setattr(groq_client, "_client", _FakeClient("NO, not supported"))
    assert judge_groundedness("masked answer", "masked context") is False


def test_judge_aborts_on_raw_value(monkeypatch):
    monkeypatch.setattr(groq_client, "_client", _FakeClient("YES"))
    # A raw value present in what we'd send must hard-fail before egress (invariant #1).
    with pytest.raises(RawSensitiveLeak):
        judge_groundedness(
            "the email is alice@example.com", "context",
            forbidden_values=["alice@example.com"],
        )
