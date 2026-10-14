# Historical validation comparison

`check_exposure_before_scan_reduction.sql` is the former `standalone/evidence_pipeline/public_receipt_validation_schema.sql` from source revision `d34acea2ac0938b005cae962a62591c20b69084d`, retained only as an independent before-optimization trigger definition. SHA-256: `11b3c2c64ce3594ad711abbf06d40e99f3725845893a99a7204d85286cae5a5b`.

The rollback-only receipt-validation test compares it with the actual installed function, counts redundant scans and preserves parent/child integrity failures. This fixture contains source code only and is not an installation, migration or repair path. The complete current definition belongs to the consolidated database baseline.
