"""Output guardrails (BUILD_SPEC section 6 / CI gate #4).

Three deterministic checks, fail-closed (a failure routes to the safe-refusal node):

  1. Non-empty answer.
  2. Invariant #6 backstop: no value the user is NOT permitted to see may appear in the
     answer. After reidentification, unpermitted fields must still be tokens; if a raw
     unpermitted value is present, something went wrong — refuse rather than leak.
  3. Groundedness: every *significant* figure in the answer must appear in the context the
     model was given (or in the user's own question). This enforces "the model narrates
     results, it does not compute them" (section 8) and blocks ungrounded/hallucinated
     numbers. A single-LLM-judge groundedness check can replace/augment this in Phase 5.
"""

from __future__ import annotations

import re

from app.models import Context, Decision, User

# Significant figures: decimals, percentages, or integers with 2+ digits. Bare single digits
# (often counts/ordinals like "3 results") are ignored to avoid false positives.
_SIGNIFICANT_NUM = re.compile(r"\d+\.\d+|\d{2,}")
_ANY_NUM = re.compile(r"\d+\.\d+|\d+")


def _significant_numbers(text: str) -> set[str]:
    return set(_SIGNIFICANT_NUM.findall(text or ""))


def check_output(answer: str, context: Context, user: User) -> Decision:  # noqa: ARG001
    if not answer or not answer.strip():
        return Decision(allow=False, reason="empty answer")

    # (2) invariant #6 backstop: unpermitted raw values must not appear.
    for value in context.unpermitted_values:
        if value and value in answer:
            return Decision(allow=False, reason="answer contains a value the user may not see")

    # (3) groundedness: no invented significant figures.
    grounding = f"{context.masked_text or ''} {context.question or ''}"
    grounding_nums = set(_ANY_NUM.findall(grounding))
    invented = {n for n in _significant_numbers(answer) if n not in grounding_nums}
    if invented:
        return Decision(
            allow=False, reason="answer contains figures not grounded in the retrieved context"
        )

    return Decision(allow=True)
