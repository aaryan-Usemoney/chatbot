"""PII detectors — find sensitive spans in free text.

The masker (app/masking/presidio_masker.py) is detector-agnostic: it tokenizes whatever spans
a ``PiiDetector`` returns. Two detectors:

  * PresidioDetector — the production detector (Microsoft Presidio + spaCy). Lazy-imported.
  * RegexPiiDetector — a dependency-free detector for high-precision pattern entities
    (email, phone, SSN, credit card). Used in CI (no spaCy model needed) and as a fallback
    for lightweight deployments. It does NOT detect NLP entities like PERSON/LOCATION.

Both return spans carrying the SAME field vocabulary used in Permissions.unmaskable_fields,
so reidentification (invariant #6) is identical regardless of detector.
"""

from __future__ import annotations

import re
from typing import Protocol

from app.config import get_settings
from app.masking.tokens import Span


class PiiDetector(Protocol):
    def detect(self, text: str) -> list[Span]: ...


# --- Regex detector (no heavy deps) -----------------------------------------------------

_REGEX_FIELDS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    # phone: simple US-ish patterns; intentionally conservative.
    ("phone", re.compile(r"\b(?:\+?1[ -]?)?(?:\(\d{3}\)|\d{3})[ -]?\d{3}-?\d{4}\b")),
]


class RegexPiiDetector:
    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for field, pattern in _REGEX_FIELDS:
            for m in pattern.finditer(text):
                spans.append(Span(start=m.start(), end=m.end(), field=field))
        return spans


# --- Presidio detector (production) -----------------------------------------------------

ENTITY_TO_FIELD: dict[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "PERSON": "person",
    "LOCATION": "location",
    "IBAN_CODE": "iban",
    "IP_ADDRESS": "ip_address",
    "US_BANK_NUMBER": "bank_account",
}
DEFAULT_ENTITIES: tuple[str, ...] = tuple(ENTITY_TO_FIELD.keys())
_SCORE_THRESHOLD = 0.5


class PresidioDetector:
    def __init__(self) -> None:
        self._analyzer = None  # lazy

    def _get_analyzer(self):
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            model = get_settings().presidio_spacy_model
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model}],
                }
            )
            self._analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
        return self._analyzer

    def detect(self, text: str) -> list[Span]:
        results = self._get_analyzer().analyze(
            text=text, language="en", entities=list(DEFAULT_ENTITIES)
        )
        spans: list[Span] = []
        for r in results:
            if r.score < _SCORE_THRESHOLD:
                continue
            field = ENTITY_TO_FIELD.get(r.entity_type, r.entity_type.lower())
            spans.append(Span(start=r.start, end=r.end, field=field))
        return spans
