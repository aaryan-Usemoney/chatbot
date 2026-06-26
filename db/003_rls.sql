-- 003_rls.sql — Row-Level Security. This is the enforced access-control mechanism for the
-- structured path (invariant #2): row visibility is decided by Postgres, never by the prompt.
--
-- Each request sets app.user_region via SET LOCAL (app/data/db.py) from resolved permissions;
-- the policy scopes rows to that region. The owner role (migrations/ingestion/audit) bypasses
-- RLS by ownership, which is intended; the read-only query role (db/005) does not.

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE sales     ENABLE ROW LEVEL SECURITY;

-- current_setting(..., true) returns NULL when unset; a NULL scope matches no rows, so an
-- unscoped connection sees nothing (fail-closed) rather than everything.
DROP POLICY IF EXISTS customers_by_region ON customers;
CREATE POLICY customers_by_region ON customers
  FOR SELECT
  USING (region = current_setting('app.user_region', true));

DROP POLICY IF EXISTS sales_by_region ON sales;
CREATE POLICY sales_by_region ON sales
  FOR SELECT
  USING (region = current_setting('app.user_region', true));

-- doc_chunks (Phase 3): metadata filtering is the documented enforcement for vector
-- retrieval (invariant #2), but we ALSO enforce it as RLS so the read-only role cannot read
-- a chunk whose access_tags don't overlap the request's app.user_tags scope, even if app code
-- forgot the filter. Created only if doc_chunks exists (i.e. pgvector was available).
-- Fail-closed: an unset/empty scope -> string_to_array(NULL/'' ) -> no overlap -> no rows.
DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'doc_chunks') THEN
    EXECUTE 'ALTER TABLE doc_chunks ENABLE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS doc_chunks_by_tags ON doc_chunks';
    EXECUTE $pol$
      CREATE POLICY doc_chunks_by_tags ON doc_chunks
        FOR SELECT
        USING (
          access_tags && string_to_array(
            nullif(current_setting('app.user_tags', true), ''), ','
          )
        )
    $pol$;
  END IF;
END $do$;
