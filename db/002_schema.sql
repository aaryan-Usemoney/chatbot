-- 002_schema.sql — tables + a small deterministic seed for local dev / integration tests.
--
-- Demonstration schema (customers, sales). Replace with the real schema; keep
-- app/data/semantic_layer.py, db/003_rls.sql, db/004_masking.sql in sync. TODO(human).

CREATE TABLE IF NOT EXISTS customers (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name           TEXT NOT NULL,
  email          TEXT,
  phone          TEXT,
  ssn            TEXT,
  region         TEXT NOT NULL,
  internal_notes TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sales (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id),
  amount      NUMERIC(12, 2) NOT NULL,
  product     TEXT NOT NULL,
  region      TEXT NOT NULL,
  sale_date   DATE NOT NULL
);

-- Audit log (BUILD_SPEC section 5). Written by the owner role only.
CREATE TABLE IF NOT EXISTS audit_log (
  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id   TEXT NOT NULL,
  question  TEXT,
  sources   JSONB,
  decision  TEXT
);

-- Documents / chunks for the Phase 3 vector path. Created only if pgvector is present.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector') THEN
    EXECUTE $ddl$
      CREATE TABLE IF NOT EXISTS doc_chunks (
        id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        document_id TEXT NOT NULL,
        content     TEXT NOT NULL,
        embedding   vector(384),
        access_tags TEXT[] NOT NULL,
        metadata    JSONB NOT NULL DEFAULT '{}'
      )
    $ddl$;
    EXECUTE 'CREATE INDEX IF NOT EXISTS doc_chunks_embedding_idx '
            'ON doc_chunks USING ivfflat (embedding vector_cosine_ops)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS doc_chunks_access_tags_idx '
            'ON doc_chunks USING gin (access_tags)';
  ELSE
    RAISE NOTICE 'skipping doc_chunks: pgvector not installed';
  END IF;
END $$;

-- ----------------------------------------------------------------------------------------
-- Deterministic seed. Two regions so access-control tests can prove zero cross-leakage.
-- These are SYNTHETIC values, not real PII.
-- ----------------------------------------------------------------------------------------
INSERT INTO customers (name, email, phone, ssn, region, internal_notes)
VALUES
  ('Alice Adams',  'alice@example.com', '555-0101', '111-11-1111', 'EMEA', 'VIP; do not email after 6pm'),
  ('Bjorn Berg',   'bjorn@example.com', '555-0102', '222-22-2222', 'EMEA', 'Net-60 terms'),
  ('Carla Cruz',   'carla@example.com', '555-0201', '333-33-3333', 'AMER', 'Prefers phone contact'),
  ('Dan Diaz',     'dan@example.com',   '555-0202', '444-44-4444', 'AMER', 'Escalation: legal hold');

INSERT INTO sales (customer_id, amount, product, region, sale_date)
VALUES
  (1, 1200.00, 'Widget Pro',  'EMEA', DATE '2026-01-15'),
  (1,  300.50, 'Widget Mini', 'EMEA', DATE '2026-02-03'),
  (2,  980.00, 'Widget Pro',  'EMEA', DATE '2026-02-20'),
  (3, 2200.00, 'Widget Max',  'AMER', DATE '2026-01-22'),
  (4,  150.00, 'Widget Mini', 'AMER', DATE '2026-03-01');
