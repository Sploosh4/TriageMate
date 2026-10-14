# Windows identity reference provenance

These public-source reference records are retained byte-for-byte from the v113 source revision recorded in `../construction.json`. They document the publishers, source URLs, content hashes and observations behind the identity/reference definitions in the consolidated SQL baseline. They are not lab evidence or runtime customer inputs. Existing record-level provenance remains authoritative; this move does not fetch or update sources.

The installation artifact manifest binds every listed record as `references/<filename>`. The complete schema signature independently binds the resulting SQL definitions. Identity tests use these records as independent expected reference data. Changes require a reviewed database revision and corresponding behavior/authority verification; deleting an installation artifact key or changing a reference file must fail current verification.
