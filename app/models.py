"""Shared domain types.

These back the type names referenced throughout BUILD_SPEC.md section 6
(``User``, ``Permissions``, ``Decision``, ``Context``, ``MaskCtx``, ``Masked``).
Keeping them in one module avoids import cycles between nodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Path(str, Enum):
    """Which retrieval path the orchestrator chose."""

    SQL = "sql"
    RETRIEVAL = "retrieval"
    REFUSE = "refuse"


@dataclass(frozen=True)
class User:
    """The authenticated principal, distilled from validated OIDC claims.

    ``raw_claims`` is kept for permission resolution but MUST NOT be logged.
    """

    subject: str
    roles: tuple[str, ...] = ()
    raw_claims: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Permissions:
    """Resolved authorization for a single request.

    This object is the single source of truth for both data-layer enforcement
    (RLS ``SET LOCAL`` scopes, ``access_tags`` filtering) and reidentification
    gating (invariant #6). It is derived from the IdP claims, never from prompts.
    """

    user_id: str
    roles: frozenset[str]
    # Domain/role tags compared against doc_chunks.access_tags (invariant #2, vector path).
    allowed_tags: frozenset[str]
    # Per-request row-scope values pushed into Postgres via SET LOCAL (e.g. {"app.user_region": "EMEA"}).
    row_scopes: dict[str, str] = field(default_factory=dict)
    # Field/entity names this user may see un-masked after synthesis (invariant #6).
    unmaskable_fields: frozenset[str] = frozenset()

    def may_unmask(self, field_name: str) -> bool:
        return field_name in self.unmaskable_fields


@dataclass
class MaskCtx:
    """Context handed to a Masker for a single request."""

    request_id: str
    permissions: Permissions
    # Optional hint of which fields are sensitive for the structured path.
    sensitive_fields: frozenset[str] = frozenset()


@dataclass
class Masked:
    """Result of masking: the de-sensitized payload plus the per-request token map.

    ``token_map`` maps token -> {"value": <raw>, "field": <field name>}. It is held
    only in the TokenVault (short TTL) and is NEVER included in any LLM prompt.
    """

    payload: dict | str
    token_map: dict[str, dict[str, str]]


@dataclass
class Citation:
    """A source attribution returned to the user alongside an answer."""

    kind: str  # "table" | "document"
    ref: str  # table name or document_id
    detail: str | None = None


@dataclass
class Context:
    """The retrieved, masked context that synthesis was grounded in.

    Used by the output guardrail (groundedness + leak backstop) and by the audit node.
    """

    path: Path
    masked_text: str
    citations: list[Citation] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    # The original question (groundedness allows figures the user themselves provided).
    question: str = ""
    # Raw values the requesting user is NOT permitted to see — must never appear in the
    # final answer (invariant #6 backstop checked by the output guardrail).
    unpermitted_values: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Decision:
    """Guardrail verdict. ``allow=False`` routes to the safe-refusal terminal node."""

    allow: bool
    reason: str | None = None
