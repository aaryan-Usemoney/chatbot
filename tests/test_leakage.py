"""Phase 5: expanded leakage / access-control coverage (invariants #1, #6)."""

from __future__ import annotations

from app.data.semantic_layer import SENSITIVE_FIELDS
from app.masking.pii_detect import RegexPiiDetector
from app.masking.presidio_masker import PresidioMasker
from app.masking.structured import StructuredTokenMasker
from app.models import MaskCtx

_VALUES = {
    "email": ["a@x.com", "b@y.com", "c@z.org"],
    "ssn": ["111-11-1111", "222-22-2222", "333-33-3333"],
    "phone": ["555-123-4567", "555-987-6543"],
}


def test_structured_battery_no_leak(analyst_perms):
    rows = (
        [{"email": e} for e in _VALUES["email"]]
        + [{"ssn": s} for s in _VALUES["ssn"]]
        + [{"phone": p} for p in _VALUES["phone"]]
    )
    masked = StructuredTokenMasker().mask(
        {"rows": rows}, MaskCtx("r", analyst_perms, SENSITIVE_FIELDS)
    )
    blob = str(masked.payload["rows"])
    for vals in _VALUES.values():
        for v in vals:
            assert v not in blob


def test_document_battery_no_leak(analyst_perms):
    text = "Mail a@x.com or b@y.com; SSNs 111-11-1111 and 222-22-2222; call 555-123-4567."
    masked = PresidioMasker(detector=RegexPiiDetector()).mask(
        text, MaskCtx("r", analyst_perms)
    )
    for vals in _VALUES.values():
        for v in vals:
            if v in text:
                assert v not in masked.payload


def test_reidentify_matrix(analyst_perms, manager_perms, admin_perms):
    """Each role sees ONLY its permitted fields; everything else stays masked."""
    masker = StructuredTokenMasker()
    row = {"email": "a@x.com", "phone": "555-123-4567", "ssn": "111-11-1111"}
    masked = masker.mask({"rows": [row]}, MaskCtx("r", analyst_perms, SENSITIVE_FIELDS))
    text = str(masked.payload["rows"])

    cases = {
        # role perms -> (visible fields, hidden fields)
        "analyst": (analyst_perms, set(), {"a@x.com", "555-123-4567", "111-11-1111"}),
        "manager": (manager_perms, {"a@x.com"}, {"555-123-4567", "111-11-1111"}),
        "admin": (admin_perms, {"a@x.com", "555-123-4567", "111-11-1111"}, set()),
    }
    for _role, (perms, visible, hidden) in cases.items():
        restored = masker.unmask(text, masked.token_map, perms)
        for v in visible:
            assert v in restored
        for v in hidden:
            assert v not in restored
