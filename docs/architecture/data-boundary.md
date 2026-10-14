# Data and evidence boundary

Operators own self-hosted deployments and choose authorized inputs. Repository development, fixtures, demonstrations and acceptance use explicitly synthetic records or public data without private access/confidentiality obligations. Label synthetic data and retain source URLs, observation times, exact bytes/hashes and upstream licenses.

Private Microsoft evidence, tenant/device identifiers, credentials, tokens, bundles and dumps stay outside Git in private deployment storage. Acceptance does not depend on customer tenants or production credentials. Preserve ignored local evidence during refactoring; the code license does not authorize publishing it.

Validate source identity, fields, scope, pagination/completeness and timestamps. Missing data is not a negative assertion. Preserve provenance and original source observations; corrections stay separately attributable. Distinguish unknown, contradictory, stale, source-reported and independently verified results.

Check Microsoft permission and entitlement for each selected input. CVSS is severity, EPSS is dated probability and KEV is a catalog assertion; none proves device applicability or authorizes device changes. Upstream licenses/terms apply independently of GPL-3.0-only.

Default access is one user on loopback. External access and multi-user permissions require separate design/authorization. Backups preserve both evidence and secrets privately. Database standards remain unchanged pending the [tradeoff discussion](REFACTOR_STANDARDS.md).
