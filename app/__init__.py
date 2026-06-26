"""Governed RAG chatbot for sensitive data.

See BUILD_SPEC.md. The non-negotiable invariants in section 0 are enforced in code,
not by convention:
  - invariant #1  -> app/llm/groq_client.py (masked-only guard)
  - invariant #2  -> db/003_rls.sql + db/005_roles.sql + app/data/db.py (read-only masked role)
  - invariant #8  -> app/nodes/sql_tool.py (single read-only SELECT validator)
"""
