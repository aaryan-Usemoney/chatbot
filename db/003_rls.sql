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
