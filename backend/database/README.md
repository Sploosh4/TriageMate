# Shared database contracts

Runtime deployment uses PostgreSQL 16 in Compose service `db`; see [container operation](../../docs/guides/CONTAINERS.md). The existing schema fingerprint, role/authority, migration and adoption machinery is retained in this first refactor pending the [database standards discussion](../../docs/architecture/REFACTOR_STANDARDS.md). Historical installation profiles are compatibility/test contracts, not separate application deployment models.

`target.load_target()` validates the selected target. `connections.local_database()` resolves it without credentials, connecting, starting PostgreSQL or installing schema. `connect()` acquires a connection only when called; the caller owns commit, rollback and close. JSON-selected targets are externally managed: selection never authorizes cluster initialization/start/stop.

`TRIAGEMATE_DATABASE_TARGET` selects an owner-only JSON target. It contains `host`, `port`, `database`, absolute private `work` and optional absolute private `credentials`; passwords belong only in protected role files. The exact host `db` is admitted only under `TRIAGEMATE_DEPLOYMENT=container`. Other retained local-target validation remains in place; this exception does not permit arbitrary remote database hosts.

Container bootstrap creates `/var/lib/triagemate/database.json` and private role files, preserves them on retry and verifies the retained supported schema. It refuses mismatching owner secrets/configuration instead of rotating or resetting them. A fresh empty database is initialized explicitly; existing installations are verified rather than silently adopted.

Owner/reader, pipeline writer and EPSS importer use separate connections and protected credential files: `credentials.json`, `pipeline-writer.json` and `epss-importer.json`. Credential readers reject symlinks, unsafe ownership/permissions, duplicate/unexpected fields, short values and oversized input before connecting. No fallback or role elevation occurs on failure. Target selection does not relocate credentials, rotate passwords or grant authority.

`installation.setup()` prepares missing restricted writer/importer files once, commits a verified baseline and checks restricted login identities; it never rotates existing secrets. Fresh fixture-free and synthetic profiles remain deliberate choices. The [baseline](baseline/README.md) is the current source; historical per-feature migration modules/dispatchers are retired. Ordinary connection consumers never install or repair schema.

`schema.install()` provides transactional fresh installation. `schema.upgrade()` uses the ordered [future-revision registry](migrations/README.md), with pre/post-state verification and rollback. Unsupported existing databases require an explicit supported transition; a fresh setup command is not an adoption mechanism.

`baseline.catalogue.fingerprint()` observes definitions and effective privileges in a caller-owned transaction with stable search-path handling. It includes non-system objects, functions, policies, triggers, role attributes/membership, default/object/database grants and built-in grants. Evidence rows and credentials are separate verification concerns. Compare against an independently constructed trusted contract, never metadata produced by the same untrusted database. Only the actual database-owner grant identity is normalized; application object ownership and other grantees stay exact.

`backup.capture()` creates a protected logical archive and stable-snapshot row/schema/sequence/metadata receipt in a new private directory. It holds write barriers, refuses path reuse and preserves failed attempts without a success receipt. `backup.restore_isolated()` requires an empty database on a different cluster, verifies archive integrity/trusted schema and every restored row, sequence and installation record. Restore passwords are supplied separately. Administrative functions do not stop application writers themselves.

`backup.verify_restored()` verifies an already imported isolated target after an interrupted comparison without reimporting or repairing it. It rejects changed receipts and refuses to overwrite completed proof. Large verification/restore checks run sequentially when concurrent scratch use would exceed disk capacity.

`adoption.adopt()` requires matching protected backup and independent restore receipts, exact source identity, unchanged annotations/predecessor/evidence and a complete source-attribution verifier. It acquires write barriers and rolls back on failure. Row hashes alone do not prove attribution or replay acceptance. The one supported v113 predecessor has exact frozen contracts and synthetic recovery fixtures; adoption is never ordinary application startup.

Exact predecessor hash alternatives and annotation exceptions are independently reconstructed and regression-tested. They are narrow accepted historical cases, not broad metadata normalization. Do not alter immutable references or weaken current checks to force adoption.

The [retained layout companion](retained_runner/README.md) handles one exact archived public revision 058 alongside evidence schema. Only that layout adds companion artifact hashes. Future revisions require independently constructed combined contracts and preserve the ledger; missing contracts/hashes or authority drift reject acceptance.
