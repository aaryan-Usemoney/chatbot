# Governed RAG Chatbot — Phases 1–2

Conversational assistant over sensitive structured **and unstructured** data with per-user
access control and LLM data-isolation. Built to `BUILD_SPEC.md`; the non-negotiable invariants
in section 0 are enforced in code, not by convention. This repo implements **Phase 1**
(skeleton, auth, audit), **Phase 2** (structured text-to-SQL path with masking), and **Phase 3**
(unstructured vector-retrieval path with in-boundary embeddings + reversible PII masking).
Phases 4–5 (formal LangGraph graph, full guardrails/groundedness, eval harness) remain.

## How the invariants are enforced

| Invariant | Mechanism | Location |
|---|---|---|
| #1 Raw sensitive never reaches the LLM | Reversible tokenization (structured) / Presidio PII masking (text) before any prompt + a hard guard that raises on egress | `app/masking/`, `app/llm/groq_client.py` |
| #2 Access control at the data layer | RLS + `SET LOCAL` scopes + read-only role (structured); `access_tags` filter + doc_chunks RLS (vector) | `db/003_rls.sql`, `app/data/db.py` |
| #4 Embeddings stay in-boundary | Self-hosted sentence-transformers; module makes no network calls | `app/data/embeddings.py` |
| #6 Reidentification is per-field, permission-gated | One shared `unmask` restores a token only if `permissions.may_unmask(field)` | `app/masking/tokens.py`, `app/nodes/reidentify.py` |
| #8 Query role is read-only | Column-scoped `SELECT`-only GRANTs + `READ ONLY` transaction + single-SELECT validator | `db/005_roles.sql`, `app/nodes/sql_tool.py` |

### Masking design decision (read this)
RLS handles **rows**. For **columns**, this build uses **app-side reversible tokenization** as
the active masking layer because reidentification (#6) requires reversibility, which the
destructive `anon` functions cannot provide. PostgreSQL Anonymizer is installed and its
column labels are declared in `db/004_masking.sql` as optional hardening, but
`anon.start_dynamic_masking()` is **deliberately not enabled** — dynamic masking routes the
masked role through views that can evaluate RLS as the view owner on older Postgres, which
would weaken invariant #2. Always-secret columns (`internal_notes`) are instead withheld via
column-level GRANTs. See the comments in `db/004_masking.sql` / `db/005_roles.sql`.

## Run locally

```bash
cp .env.example .env          # set GROQ_API_KEY; keep AUTH_DEV_MODE=true for local
docker compose up --build     # postgres(+anon/pgvector) + redis + api
# API on http://localhost:8000  (POST /chat, GET /healthz)
```

A dev bearer token (HS256, signed with `AUTH_DEV_HS256_SECRET`) is accepted only when
`AUTH_DEV_MODE=true` and `APP_ENV != production`. In real environments set the `OIDC_*` vars;
RS256/JWKS validation then takes over automatically.

## Tests

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest                        # unit tests (no DB / network / spaCy needed)
RUN_INTEGRATION=1 pytest      # also runs RLS / read-only / doc-RLS tests (needs docker compose up)
RUN_PRESIDIO=1 pytest         # also runs the live Presidio detector test (needs spaCy model)
```

PII masking detection is pluggable (`app/masking/pii_detect.py`): production uses
`PresidioDetector` (Presidio + spaCy); a dependency-free `RegexPiiDetector` (email/phone/SSN/
card) drives the masking core in CI and serves as a lightweight-deployment fallback. The
masking/token/reidentification logic is identical either way.

CI gates (BUILD_SPEC section 9): `test_no_raw_sensitive_in_prompt`, `test_access_control`,
`test_masking_roundtrip`, `test_guardrails` (+ `test_sql_validation`, `test_auth`).

## Acceptance status

- **Phase 1** — streaming `/chat`, OIDC/dev JWT validation, `resolve_permissions`, audit row
  per request, docker-compose stack. ✅ (HTTP end-to-end check requires the live stack.)
- **Phase 2** — `001`–`005` migrations, text-to-SQL with single-read-only-SELECT validation,
  execution under the masked read-only role with `SET LOCAL` RLS scopes, app-side masking;
  `test_no_raw_sensitive_in_prompt` green for the structured path. ✅
- **Phase 3** — local embeddings (`embeddings.py`), `ingest.py` (chunk→embed→index with
  `access_tags`), retrieval node (pgvector similarity + `access_tags` filter + doc_chunks RLS),
  reversible Presidio PII masking before synthesis; `test_no_raw_sensitive_in_prompt` green for
  the unstructured path; document text never leaves the boundary for embedding (invariant #4).
  ✅ (live pgvector retrieval + ingest verified via the gated integration test.)

### Storage policy note (Phase 3)
Chunk `content` is stored **original** (inside the trust boundary) and masked reversibly at
retrieval, so authorized users can be re-identified per field. If policy requires
masked-at-rest, mask before insert in `ingest.py` (marked `TODO(human)`).

## Remaining (Phases 4–5)
Formal LangGraph compiled graph, full input/output guardrails incl. groundedness, citations
polish, eval harness + metrics. Items needing org input are marked `TODO(human)` (real schema,
claim→scope mapping, sensitive-field catalogue, spaCy model choice).
