-- 001_extensions.sql — extensions.
-- Runs first (lexical order) on an empty data dir via docker-entrypoint-initdb.d.
--
-- pgcrypto: hashing / random helpers.
-- anon (PostgreSQL Anonymizer): column masking labels (db/004). Requires the extension to be
--   preloaded (the dalibo/postgresql_anonymizer image does this via shared_preload_libraries).
-- vector (pgvector): doc_chunks embeddings — only needed for the Phase 3 unstructured path.
--
-- anon and vector are wrapped so a base image lacking them does not abort init; the enforced
-- security for Phases 1-2 (RLS, column GRANTs, app-side tokenization) does not depend on either.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS anon CASCADE;
  PERFORM anon.init();
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'anon extension unavailable (column-masking labels will be skipped): %', SQLERRM;
END $$;

DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgvector unavailable (Phase 3 retrieval needs it; doc_chunks will be skipped): %', SQLERRM;
END $$;
