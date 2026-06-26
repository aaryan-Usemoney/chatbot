-- 004_masking.sql — PostgreSQL Anonymizer column masking (defense in depth).
--
-- Design note (important): the ENFORCED column protection in this build is:
--   * RLS for rows (003),
--   * column-level GRANTs to withhold always-secret columns from the read-only role (005), and
--   * app-side reversible tokenization for fields that some roles may re-identify (invariant #6,
--     app/masking/structured.py) — anon's masking is destructive and cannot support per-field,
--     permission-gated re-identification.
--
-- anon labels are declared here as an OPTIONAL hardening layer. We deliberately do NOT call
-- anon.start_dynamic_masking(): dynamic masking routes the masked role through views in the
-- `mask` schema, and pre-PG15 those views can evaluate RLS as the view owner — which would
-- weaken invariant #2. Enabling it requires verifying security_invoker semantics on the target
-- Postgres first. Until then the labels are declarative and the GRANTs in 005 do the work.
--
-- TODO(human): if dynamic masking is desired, confirm view security_invoker on the target
-- version, then uncomment the activation in db/005_roles.sql.

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'anon') THEN
    -- internal_notes: free text that may contain secrets; no role re-identifies it.
    EXECUTE 'SECURITY LABEL FOR anon ON COLUMN customers.internal_notes '
            'IS ''MASKED WITH VALUE ''''[REDACTED]''''''';
    -- ssn: labeled for the optional dynamic-masking profile (dollar-quoted to avoid quote
    -- doubling). The reversible app-side layer is what actually serves authorized
    -- re-identification today.
    EXECUTE 'SECURITY LABEL FOR anon ON COLUMN customers.ssn '
            'IS ''MASKED WITH FUNCTION anon.partial(ssn,0,$x$XXX-XX-$x$,4)''';
  ELSE
    RAISE NOTICE 'anon not installed; skipping column masking labels';
  END IF;
END $do$;
