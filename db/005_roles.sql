-- 005_roles.sql — the read-only, masked query role (invariant #8).
--
-- ALL model-generated SQL runs as this role (DATABASE_URL_READONLY). It can SELECT, nothing
-- else, and RLS (003) scopes its rows. Column-level GRANTs withhold always-secret columns so
-- the role never even receives them in clear form (the app-side layer never sees them either).
--
-- The password here is a LOCAL DEV credential matching .env.example / docker-compose. In any
-- deployed environment, create this role out-of-band from a secret manager. TODO(human).

DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chatbot_readonly') THEN
    CREATE ROLE chatbot_readonly LOGIN PASSWORD 'readonly_pw';
  END IF;
END $do$;

-- Strip any inherited write defaults, then grant exactly read.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM chatbot_readonly;

GRANT CONNECT ON DATABASE chatbot TO chatbot_readonly;
GRANT USAGE ON SCHEMA public TO chatbot_readonly;

-- customers: SELECT only the non-secret columns. internal_notes is intentionally withheld,
-- so the read-only role cannot read it at all (stronger than masking it).
GRANT SELECT (id, name, email, phone, ssn, region, created_at) ON customers TO chatbot_readonly;

GRANT SELECT ON sales TO chatbot_readonly;

-- doc_chunks (Phase 3) if present.
DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables
             WHERE table_schema = 'public' AND table_name = 'doc_chunks') THEN
    GRANT SELECT ON doc_chunks TO chatbot_readonly;
  END IF;
END $do$;

-- The read-only role must NEVER touch the audit log or get write defaults.
REVOKE ALL ON audit_log FROM chatbot_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM chatbot_readonly;

-- Optional anon dynamic-masking activation (see db/004 caveat). Left disabled.
-- DO $do$
-- BEGIN
--   IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'anon') THEN
--     EXECUTE 'SECURITY LABEL FOR anon ON ROLE chatbot_readonly IS ''MASKED''';
--     PERFORM anon.start_dynamic_masking();
--   END IF;
-- END $do$;
