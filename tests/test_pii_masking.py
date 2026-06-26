"""Phase 3: reversible PII masking over free text (CI gate #3, unstructured path).

The dependency-free RegexPiiDetector exercises the full masking core + reidentification
gating. A separate, gated test validates the real Presidio detector when available.
"""

from __future__ import annotations

import pytest

from app.masking.pii_detect import RegexPiiDetector
from app.masking.presidio_masker import PresidioMasker
from app.models import MaskCtx

TEXT = "Email alice@example.com, call 555-123-4567, SSN 111-11-1111."


def _mask(perms):
    masker = PresidioMasker(detector=RegexPiiDetector())
    masked = masker.mask(TEXT, MaskCtx(request_id="r", permissions=perms))
    return masker, masked


def test_pii_is_tokenized(analyst_perms):
    _, masked = _mask(analyst_perms)
    for raw in ("alice@example.com", "555-123-4567", "111-11-1111"):
        assert raw not in masked.payload


def test_reidentification_is_permission_gated(manager_perms, admin_perms, analyst_perms):
    masker, masked = _mask(admin_perms)
    text = masked.payload

    out_analyst = masker.unmask(text, masked.token_map, analyst_perms)
    assert "alice@example.com" not in out_analyst  # analyst un-masks nothing

    out_manager = masker.unmask(text, masked.token_map, manager_perms)
    assert "alice@example.com" in out_manager  # manager may see email
    assert "111-11-1111" not in out_manager  # but not ssn

    out_admin = masker.unmask(text, masked.token_map, admin_perms)
    assert "alice@example.com" in out_admin
    assert "111-11-1111" in out_admin
    assert "555-123-4567" in out_admin


def test_tokens_deterministic_across_chunks(analyst_perms):
    masker = PresidioMasker(detector=RegexPiiDetector())
    payload = {
        "chunks": [
            {"document_id": "d1", "content": "reach alice@example.com"},
            {"document_id": "d1", "content": "again alice@example.com"},
        ]
    }
    masked = masker.mask(payload, MaskCtx(request_id="r", permissions=analyst_perms))
    c0, c1 = masked.payload["chunks"]
    tok0 = c0["content"].split()[-1]
    tok1 = c1["content"].split()[-1]
    assert tok0 == tok1  # same email -> same token
    assert "alice@example.com" not in (c0["content"] + c1["content"])


@pytest.mark.presidio
def test_presidio_detector_masks_person_and_email(analyst_perms):
    pytest.importorskip("presidio_analyzer")
    from app.masking.pii_detect import PresidioDetector

    detector = PresidioDetector()
    try:
        spans = detector.detect("Contact John Smith at john@example.com")
    except Exception as exc:  # missing spaCy model, etc.
        pytest.skip(f"Presidio/spaCy unavailable: {exc}")

    fields = {s.field for s in spans}
    assert "email" in fields
    assert "person" in fields
