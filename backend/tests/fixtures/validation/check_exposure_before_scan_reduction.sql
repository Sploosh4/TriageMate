-- Inserting a receipt unrelated to an exposure snapshot cannot invalidate an
-- existing device/exposure link. Actual child inserts and every parent edit or
-- deletion retain validation. Check at deferred-constraint time, so a snapshot
-- added later in the same transaction is still included.
CREATE OR REPLACE FUNCTION evidence_pipeline.check_exposure() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' AND TG_TABLE_SCHEMA='evidence'
    AND TG_TABLE_NAME='observation_receipts' THEN
  IF NOT EXISTS (SELECT 1 FROM evidence_pipeline.exposure_snapshots s
                 WHERE s.collection_attempt_id=NEW.collection_attempt_id) THEN
   RETURN NULL;
  END IF;
 END IF;
 IF TG_OP='INSERT' AND TG_TABLE_SCHEMA='evidence' AND TG_TABLE_NAME='patches' THEN
  IF NOT EXISTS (SELECT 1 FROM evidence.device_missing_patches p
                 WHERE p.patch_id=NEW.id) THEN
   RETURN NULL;
  END IF;
 END IF;
 PERFORM evidence_pipeline.validate_exposure();
 RETURN NULL;
END $$;
