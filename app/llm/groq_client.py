"""Groq client — the single external egress point.

Defense in depth around invariant #1: every prompt that leaves this process is scanned
for known raw sensitive values first; if any are present the call RAISES (we never
log-and-continue, BUILD_SPEC section 12). Invariant #5: this is the only external network
call, and the account must have Zero Data Retention enabled (gated by GROQ_ZDR_CONFIRMED).

No business logic lives here (section 12): it constructs no domain prompts and makes no
authorization decisions. It transports masked text and streams tokens back.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from openai import OpenAI

from app.config import get_settings


class RawSensitiveLeak(Exception):
    """Raised when content bound for the LLM still contains a raw sensitive value."""


class ZDRNotConfirmed(Exception):
    """Raised when egress is attempted without Zero Data Retention confirmed."""


def assert_contains_no_raw_sensitive(
    prompt: str, forbidden_values: Iterable[str] = ()
) -> None:
    """Scan ``prompt`` for any raw sensitive value; raise if found.

    ``forbidden_values`` are the raw values that the masking layer replaced for this request
    (the values held in the TokenVault). If any survived into the prompt, masking failed and
    we must abort before egress.
    """
    for value in forbidden_values:
        if value and str(value) in prompt:
            # Do NOT include the value in the error message (invariant #7).
            raise RawSensitiveLeak(
                "prompt contains a raw sensitive value that should have been masked"
            )


_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        settings = get_settings()
        if not settings.groq_zdr_confirmed:
            raise ZDRNotConfirmed(
                "GROQ_ZDR_CONFIRMED must be true before any prompt is sent to Groq"
            )
        _client = OpenAI(
            api_key=settings.groq_api_key.get_secret_value(),
            base_url=settings.groq_base_url,
        )
    return _client


def _messages(system: str, user: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def synthesize(
    masked_prompt: str,
    *,
    system_prompt: str = "",
    forbidden_values: Iterable[str] = (),
    temperature: float = 0.0,
) -> str:
    """Non-streaming completion over masked content. Returns the full answer text."""
    assert_contains_no_raw_sensitive(masked_prompt, forbidden_values)
    if system_prompt:
        assert_contains_no_raw_sensitive(system_prompt, forbidden_values)
    settings = get_settings()
    resp = _get_client().chat.completions.create(
        model=settings.groq_model,
        messages=_messages(system_prompt, masked_prompt),
        temperature=temperature,
    )
    return resp.choices[0].message.content or ""


def synthesize_stream(
    masked_prompt: str,
    *,
    system_prompt: str = "",
    forbidden_values: Iterable[str] = (),
    temperature: float = 0.0,
) -> Iterator[str]:
    """Streaming completion over masked content. Yields token deltas."""
    assert_contains_no_raw_sensitive(masked_prompt, forbidden_values)
    if system_prompt:
        assert_contains_no_raw_sensitive(system_prompt, forbidden_values)
    settings = get_settings()
    stream = _get_client().chat.completions.create(
        model=settings.groq_model,
        messages=_messages(system_prompt, masked_prompt),
        temperature=temperature,
        stream=True,
    )
    for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            yield delta
