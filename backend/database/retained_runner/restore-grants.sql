-- Derived from 77d44c2bb7e2ceb61fbe4c8864ea49246d239491 backend/tests/conftest.py.

GRANT triagemate_retention_approver,triagemate_retention_executor TO triagemate;

DO $$ DECLARE signature text; BEGIN
                  FOR signature IN SELECT DISTINCT p.oid::regprocedure::text
                  FROM pg_proc p WHERE p.pronamespace='pg_catalog'::regnamespace
                  AND (p.oid IN (SELECT oprcode FROM pg_operator
                                WHERE oprnamespace='pg_catalog'::regnamespace)
                    OR p.oid IN (SELECT castfunc FROM pg_cast WHERE castfunc<>0)
                    OR p.oid IN (SELECT typoutput FROM pg_type
                                WHERE typnamespace='pg_catalog'::regnamespace))
                  LOOP EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO
                    triagemate_retention_approver,triagemate_retention_executor,
                    triagemate_test_application',signature); END LOOP;
                END $$;

GRANT EXECUTE ON FUNCTION
                  pg_catalog.hashtextextended(text,bigint),
                  pg_catalog.pg_advisory_xact_lock(bigint),
                  pg_catalog.pg_advisory_xact_lock_shared(bigint),
                  pg_catalog.max(text),pg_catalog.max(timestamptz),
                  pg_catalog.count()
                TO triagemate_retention_approver,triagemate_retention_executor;

GRANT EXECUTE ON FUNCTION pg_catalog.to_regrole(text),
                  pg_catalog.pg_has_role(name,oid,text),
                  pg_catalog.current_setting(text,boolean)
                TO triagemate_test_application;
