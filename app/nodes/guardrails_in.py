"""Input guardrails (BUILD_SPEC section 6).

Phase 2 ships a conservative, deterministic input guard: length bounds and obvious
prompt-injection / jailbreak markers. Phase 4 expands this (Presidio PII on input,
out-of-scope classification). A failed check routes to the safe-refusal terminal node.

Note: these guardrails are a usability/abuse layer. They are NOT the access-control or
data-isolation mechanism — those are the data layer (invariant #2) and masking (invariant #1).
"""

from __future__ import annotations

import re

from app.models import Decision, User

_MAX_LEN = 4000

# Heuristic markers for prompt-injection / jailbreak attempts.
_INJECTION_PATTERNS = (
    r"ignore (all |the )?(previous|prior|above) instructions",
    r"disregard (all |the )?(previous|prior|above)",
    r"you are now",
    r"reveal (your )?(system|developer) prompt",
    r"print (your )?(system|developer) prompt",
    r"bypass (the )?(masking|guardrail|access control|rls)",
    r"show me the raw (ssn|email|phone|data|values)",
    r"act as (an? )?(unrestricted|jailbroken)",
)
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

# Conservative out-of-scope markers: clearly off-domain creative/general-assistant requests.
# Kept narrow to avoid refusing legitimate data questions.
_OUT_OF_SCOPE_PATTERNS = (
    r"\bwrite (me )?(a|an) (poem|song|story|joke|essay|script)\b",
    r"\btell me a joke\b",
    r"\bwhat'?s the weather\b",
    r"\b(translate|summarize) this (text|article|paragraph)\b",
    r"\bwrite (some )?(python|javascript|sql|code) (for|to)\b",
)
_OUT_OF_SCOPE_RE = re.compile("|".join(_OUT_OF_SCOPE_PATTERNS), re.IGNORECASE)


def check_input(message: str, user: User) -> Decision:  # noqa: ARG001
    text = (message or "").strip()
    if not text:
        return Decision(allow=False, reason="empty message")
    if len(text) > _MAX_LEN:
        return Decision(allow=False, reason="message too long")
    if _INJECTION_RE.search(text):
        return Decision(allow=False, reason="input rejected by injection guardrail")
    if _OUT_OF_SCOPE_RE.search(text):
        return Decision(allow=False, reason="out-of-scope request")
    return Decision(allow=True)
