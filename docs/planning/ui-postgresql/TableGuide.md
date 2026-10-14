# Synthetic database fixture reference

The retained fixture data defines the original 47-table synthetic model and its independent expected column/relationship/view contracts. It is historical test data, not a complete current runtime inventory or a plan to expose every table in the product. Runtime definitions and signatures live in `backend/database/baseline/` and explicit supported revisions.

| Reference | Purpose |
|---|---|
| [SchemaColumns.csv](SchemaColumns.csv) | Original types, keys and nullability |
| [SchemaRelationships.csv](SchemaRelationships.csv) | Original relation expectations |
| [ViewColumns.csv](ViewColumns.csv) | Original view column expectations |
| [SourceFieldCrosswalk.csv](SourceFieldCrosswalk.csv) | Historical source-to-field crosswalk; proposed mappings are not current implementation claims |
| [SyntheticFixtureCounts.csv](SyntheticFixtureCounts.csv) | Synthetic baseline row counts |
| [CompletenessTestFixtures.json](CompletenessTestFixtures.json) | Synthetic completeness scenarios |

These records are consumed by backend/database tests and remain unchanged in this refactor. Baseline fixtures are explicitly synthetic. Do not infer actual collection coverage, entitlement or installed-product applicability from them. Database standards await the [tradeoff discussion](../../architecture/REFACTOR_STANDARDS.md).
