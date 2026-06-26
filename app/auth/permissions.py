"""Permission resolution: validated claims -> ``Permissions``.

This is the mapping from SSO claims to the authorization facts the data layer enforces.
Per BUILD_SPEC section 11 ("Permission granularity"), the exact claim->scope mapping is
deployment-specific; the structure here supports per-row (row_scopes), per-domain
(allowed_tags), and per-field (unmaskable_fields) scoping simultaneously.

TODO(human): replace ``_CLAIM_MAP`` and ``_ROLE_POLICY`` with the real claim names and
the org's role -> (tags, row-scopes, unmaskable-fields) policy. Until then this uses
conservative, least-privilege defaults driven by standard OIDC claim shapes.
"""

from __future__ import annotations

from typing import Any

from app.models import Permissions, User


class PermissionError_(Exception):
    """Raised when permissions cannot be resolved; the request must be refused."""


def user_from_claims(claims: dict[str, Any]) -> User:
    subject = claims.get("sub")
    if not subject:
        raise PermissionError_("token has no subject")
    roles = _extract_roles(claims)
    return User(subject=str(subject), roles=tuple(roles), raw_claims=claims)


def _extract_roles(claims: dict[str, Any]) -> list[str]:
    # Accept the common shapes: top-level "roles", or realm/resource access (Keycloak),
    # or a space-delimited "scope". TODO(human): pin to the real IdP shape.
    roles: list[str] = []
    if isinstance(claims.get("roles"), list):
        roles += [str(r) for r in claims["roles"]]
    realm = claims.get("realm_access")
    if isinstance(realm, dict) and isinstance(realm.get("roles"), list):
        roles += [str(r) for r in realm["roles"]]
    return sorted(set(roles))


# --- Deployment policy stubs (replace with real org policy) -----------------------------

# Maps a claim name -> the Postgres GUC used in RLS policies (SET LOCAL <guc> = <claim value>).
_CLAIM_MAP: dict[str, str] = {
    "region": "app.user_region",
    "department": "app.user_department",
}

# Role -> (vector access_tags, fields the role may un-mask). Least privilege by default.
_ROLE_POLICY: dict[str, dict[str, frozenset[str]]] = {
    "analyst": {
        "tags": frozenset({"sales", "marketing"}),
        "unmask": frozenset(),  # analysts see masked PII only
    },
    "manager": {
        "tags": frozenset({"sales", "marketing", "hr"}),
        "unmask": frozenset({"email"}),
    },
    "admin": {
        "tags": frozenset({"sales", "marketing", "hr", "finance"}),
        "unmask": frozenset({"email", "phone", "ssn"}),
    },
}


def resolve_permissions(user: User) -> Permissions:
    """Resolve a ``User`` (from validated claims) into request ``Permissions``.

    Raises ``PermissionError_`` if no usable authorization can be derived — the caller
    must then refuse the request (BUILD_SPEC section 8).
    """
    claims = user.raw_claims

    # Row scopes from mapped claims (drive RLS via SET LOCAL).
    row_scopes: dict[str, str] = {}
    for claim_name, guc in _CLAIM_MAP.items():
        value = claims.get(claim_name)
        if value is not None and value != "":
            row_scopes[guc] = str(value)

    # Aggregate domain tags and unmaskable fields across the user's roles.
    allowed_tags: set[str] = set()
    unmaskable: set[str] = set()
    for role in user.roles:
        policy = _ROLE_POLICY.get(role)
        if policy:
            allowed_tags |= set(policy["tags"])
            unmaskable |= set(policy["unmask"])

    if not user.roles:
        raise PermissionError_("no roles present on token")
    if not allowed_tags and not row_scopes:
        # A principal with zero data scope can answer nothing; refuse rather than
        # silently returning empty results that look like "no data".
        raise PermissionError_("no data scope resolved for principal")

    return Permissions(
        user_id=user.subject,
        roles=frozenset(user.roles),
        allowed_tags=frozenset(allowed_tags),
        row_scopes=row_scopes,
        unmaskable_fields=frozenset(unmaskable),
    )
