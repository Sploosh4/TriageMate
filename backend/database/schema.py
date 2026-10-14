"""Explicit consolidated-schema installation and verification.

All entry points use a caller-owned transaction. Importing this module performs
no database, credential or filesystem mutations. Existing installations are
verified rather than repaired; predecessor adoption is a separate operation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from psycopg2 import sql
from psycopg2.extensions import cursor
from psycopg2.extras import Json

from .baseline.catalogue import fingerprint, require_contract
from .baseline.profiles import PROFILES, identify_layout, read_contract
from .migrations import revisions
from .metadata import annotation, legacy_annotation_matches
from . import retained_runner

BASE = Path(__file__).with_name("baseline")
VERSION = "triagemate-baseline-v1"
OWNER = "tm_mock_owner"
FILES = (
    "schema.sql",
    "current-contract.json",
    "predecessor-contract.json",
    "privileges.json",
    "construction.json",
    "fixtures.json",
    "predecessor-metadata.json",
    "original-tables.json",
    "legacy-annotations.json",
    "synthetic-grants.sql",
    "references/windows_cbs_identities.json",
    "references/windows_cloud_identity.json",
    "references/windows_component_references.json",
    "references/windows_framework_identities.json",
    "references/windows_inbox_identities.json",
    "references/windows_media_identities.json",
    "references/windows_native_framework_identities.json",
    "references/windows_package_identities.json",
    "references/windows_runtime_releases.json",
    "references/windows_security_app_identity.json",
    "references/windows_store_extension_identities.json",
    "references/windows_store_identities.json",
    "references/windows_store_system_identities.json",
    "references/windows_system_component_extensions.json",
    "references/windows_system_identities.json",
    *(
        f"profiles/{profile}/{name}"
        for profile in ("synthetic", "runner")
        for name in (
            "predecessor-contract.json",
            "current-contract.json",
            "privileges.json",
        )
    ),
)
LOGIN_ROLES = ("tm_mock_reader", "tm_epss_importer", "tm_pipeline_writer")
FUNCTION_ROLES = (
    "tm_classification_function",
    "tm_epss_function",
    "tm_mock_fixture",
    "tm_notification_function",
)


@dataclass(frozen=True)
class InstallPasswords:
    reader: str
    importer: str
    writer: str

    def validated(self) -> dict[str, str]:
        values = dict(
            zip(LOGIN_ROLES, (self.reader, self.importer, self.writer), strict=True)
        )
        if any(
            not isinstance(value, str) or len(value) < 32 or "\0" in value
            for value in values.values()
        ):
            raise ValueError(
                "Three distinct pre-provisioned login secrets of at least 32 characters are required"
            )
        if len(set(values.values())) != len(values):
            raise ValueError("Database login secrets must be distinct")
        return values


def latest_version() -> str:
    ordered = revisions()
    return ordered[-1].version if ordered else VERSION


def artifacts(version: str = VERSION, *, retained: bool = False) -> dict[str, str]:
    result = {
        name: hashlib.sha256((BASE / name).read_bytes()).hexdigest() for name in FILES
    }
    if retained:
        result.update(retained_runner.artifacts())
    if version == VERSION:
        return result
    for migration in revisions():
        result[f"migration/{migration.version}/sql"] = hashlib.sha256(
            migration.source.read_bytes()
        ).hexdigest()
        for index, path in enumerate(migration.contracts):
            result[f"migration/{migration.version}/contract/{index}"] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
        for index, path in enumerate(migration.retained_runner_contracts):
            result[
                f"migration/{migration.version}/retained-runner-contract/{index}"
            ] = hashlib.sha256(path.read_bytes()).hexdigest()
        if migration.version == version:
            return result
    raise ValueError("Unsupported database version")


def _read_contract(path: Path) -> dict[str, str]:
    value = json.loads(path.read_text())
    if (
        not isinstance(value, dict)
        or not value
        or any(
            not isinstance(key, str) or not isinstance(digest, str) or len(digest) != 64
            for key, digest in value.items()
        )
    ):
        raise ValueError("Invalid checked-in schema contract")
    return dict(value)


def contract(*, predecessor: bool = False, profile: str = "empty") -> dict[str, str]:
    return read_contract(profile, predecessor=predecessor)


def _contracts(version: str) -> tuple[dict[str, str], ...]:
    if version == VERSION:
        return tuple(
            contract(profile=profile, predecessor=predecessor)
            for profile in PROFILES
            for predecessor in (False, True)
        ) + tuple(retained_runner.contract(predecessor=old) for old in (False, True))
    for migration in revisions():
        if migration.version == version:
            return tuple(
                _read_contract(path) for path in migration.contracts
            ) + _retained_contracts(version)
    raise ValueError("Unsupported database version")


def _retained_contracts(version: str) -> tuple[dict[str, str], ...]:
    if version == VERSION:
        return tuple(retained_runner.contract(predecessor=old) for old in (False, True))
    for migration in revisions():
        if migration.version == version:
            return tuple(
                _read_contract(path) for path in migration.retained_runner_contracts
            )
    raise ValueError("Unsupported database version")


def _authority(cur: cursor, database: str) -> None:
    if cur.connection.autocommit:
        raise ValueError("Schema operations require a caller-owned transaction")
    cur.execute(
        "SELECT current_database(),current_user,current_setting('server_version_num')::integer"
    )
    row = cur.fetchone()
    if row is None or row[:2] != (database, OWNER) or not 160000 <= row[2] < 170000:
        raise ValueError("Explicit PostgreSQL 16 target and application owner required")
    cur.execute("SELECT pg_advisory_xact_lock(731904215)")
    cur.execute("SELECT pg_advisory_xact_lock(731904216)")
    cur.execute("SELECT pg_advisory_xact_lock(731904217)")


def installed_version(cur: cursor) -> str | None:
    cur.execute("SELECT to_regclass('evidence_pipeline.installation')")
    row = cur.fetchone()
    if row is None or row[0] is None:
        return None
    cur.execute("SELECT version FROM evidence_pipeline.installation WHERE singleton")
    rows = cur.fetchall()
    if len(rows) != 1:
        raise ValueError("Exactly one installation record required")
    version: str = rows[0][0]
    return version


def require_current_version(cur: cursor) -> None:
    """Writer-safe version guard using only its granted installation column.

    Explicit registration/startup performs complete schema/authority verification.
    Restricted ingestion does not acquire owner access to installation metadata.
    """
    cur.execute("SELECT version FROM evidence_pipeline.installation WHERE singleton")
    if cur.fetchone() != (latest_version(),):
        raise ValueError("Explicit consolidated database migration required")


def verify(cur: cursor, *, require_latest: bool = True) -> None:
    """Check supported version, immutable artifacts and an exact trusted schema."""
    version = installed_version(cur)
    if version is None or (require_latest and version != latest_version()):
        raise ValueError(
            "Unsupported database version; explicit verified adoption or upgrade required"
        )
    expected_contracts = _contracts(version)
    cur.execute(
        "SELECT artifacts,signature FROM evidence_pipeline.installation WHERE singleton"
    )
    row = cur.fetchone()
    retained = bool(
        row
        and isinstance(row[0], dict)
        and any(key.startswith(retained_runner.PREFIX) for key in row[0])
    )
    if (
        row is None
        or row[0] != artifacts(version, retained=retained)
        or row[1] not in expected_contracts
    ):
        raise ValueError("Installation artifact or signature metadata differs")
    if retained != (row[1] in _retained_contracts(version)):
        raise ValueError("Installation retained runner artifact selection differs")
    require_contract(fingerprint(cur), row[1])
    if retained:
        retained_runner.verify(cur)
    if version == VERSION:
        profile, _ = identify_layout(row[1])
        cur.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        recorded = cur.fetchone()
        try:
            decoded = json.loads(recorded[0] or "null") if recorded else None
        except (ValueError, TypeError):
            decoded = None
        if decoded != annotation(profile):
            raise ValueError("Current installation annotation differs")


def upgrade(cur: cursor, *, database: str) -> bool:
    """Apply explicitly registered future revisions atomically and in order.

    Every step checks its pre-state, executes immutable SQL, checks the trusted
    post-state and updates the installation ledger in the caller's transaction.
    Unknown versions and modified prior artifacts are refused without recovery.
    """
    _authority(cur, database)
    verify(cur, require_latest=False)
    version = installed_version(cur)
    cur.execute("SELECT artifacts FROM evidence_pipeline.installation WHERE singleton")
    ledger = cur.fetchone()
    retained = bool(
        ledger and any(key.startswith(retained_runner.PREFIX) for key in ledger[0])
    )
    ordered = revisions()
    versions = (VERSION, *(migration.version for migration in ordered))
    if version not in versions:
        raise ValueError("Unsupported database version")
    start = versions.index(version)
    changed = False
    for migration in ordered[start:]:
        cur.execute(migration.source.read_text())
        actual = fingerprint(cur)
        if actual not in _contracts(migration.version):
            raise ValueError("Migration post-state differs from its trusted contract")
        cur.execute(
            "UPDATE evidence_pipeline.installation SET version=%s,artifacts=%s,signature=%s WHERE singleton",
            (
                migration.version,
                Json(artifacts(migration.version, retained=retained)),
                Json(actual),
            ),
        )
        verify(cur, require_latest=False)
        changed = True
    verify(cur)
    return changed


def verify_predecessor(cur: cursor) -> str:
    """Read-only verification of the sole deployed pre-baseline state.

    Restored backups may have the exact current deparsed layout while retaining
    the original installation record; both independently trusted layouts count.
    This is an adoption/readability boundary, not an old-version upgrade chain.
    """
    expected = json.loads((BASE / "predecessor-metadata.json").read_text())
    construction = json.loads((BASE / "construction.json").read_text())
    if installed_version(cur) != expected["predecessor"]:
        raise ValueError("Unsupported predecessor database version")
    actual = fingerprint(cur)
    profile, _ = identify_layout(actual)
    retained = retained_runner.matches(actual)
    if retained:
        retained_runner.verify(cur)
    cur.execute(
        "SELECT artifacts,signature FROM evidence_pipeline.installation WHERE singleton"
    )
    row = cur.fetchone()
    if row is None or row[0] != construction["predecessor_artifacts"]:
        raise ValueError("Predecessor installation artifacts differ")
    digest = hashlib.sha256(
        json.dumps(row[1], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # Exact independently reconstructed predecessor variants only. Do not sort
    # arbitrary metadata or use the current database to bless its own signature.
    signatures = [expected["signature_sha256"][profile]] + expected.get(
        "signature_alternatives_sha256", {}
    ).get(profile, [])
    if retained:
        signatures = [retained_runner.predecessor_signature()]
    if digest not in signatures:
        raise ValueError("Predecessor installation signature differs")
    cur.execute(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
    )
    recorded = cur.fetchone()
    try:
        decoded = json.loads(recorded[0] or "null") if recorded else None
    except (ValueError, TypeError):
        decoded = None
    if not legacy_annotation_matches(profile, decoded):
        raise ValueError("Predecessor installation annotation differs")
    return profile


def verify_supported(cur: cursor) -> None:
    """Verify current schema or the one explicitly supported adoption predecessor."""
    if installed_version(cur) == "pipeline-windows-os-native-facts-v113":
        verify_predecessor(cur)
    else:
        verify(cur)


def _require_empty(cur: cursor) -> None:
    cur.execute(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
    )
    row = cur.fetchone()
    if row is None or row[0] is not None:
        raise ValueError(
            "Database is already annotated; installation refuses to overwrite it"
        )
    cur.execute(
        "SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema')"
    )
    if cur.fetchall():
        raise ValueError("Database has existing user schemas")
    cur.execute("""
        SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace
        UNION ALL SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace
        UNION ALL SELECT 1 FROM pg_type WHERE typnamespace='public'::regnamespace
    """)
    if cur.fetchone():
        raise ValueError("Database has existing public objects")
    cur.execute("SELECT rolname FROM pg_roles WHERE left(rolname,3)='tm_'")
    if {row[0] for row in cur.fetchall()} != {OWNER}:
        raise ValueError("Reserved application roles already exist")


def _roles(cur: cursor, passwords: Mapping[str, str]) -> None:
    for role in FUNCTION_ROLES:
        cur.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(role))
        )
    for role, password in passwords.items():
        limit = -1 if role == "tm_pipeline_writer" else 4
        cur.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {}"
            ).format(sql.Identifier(role), sql.Literal(limit)),
            (password,),
        )
    for name, value in (
        ("default_transaction_read_only", "on"),
        ("statement_timeout", "20s"),
        ("lock_timeout", "20s"),
    ):
        cur.execute(
            sql.SQL("ALTER ROLE tm_mock_reader SET {} TO %s").format(
                sql.Identifier(name)
            ),
            (value,),
        )


def _privileges(cur: cursor, database: str, *, profile: str = "empty") -> None:
    if profile not in PROFILES:
        raise ValueError("Unknown database installation profile")
    folder = BASE if profile == "empty" else BASE / "profiles" / profile
    value = json.loads((folder / "privileges.json").read_text())
    cur.execute(
        sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(
            sql.Identifier(database)
        )
    )
    for role, privilege, grantable in value["database"]:
        if (
            role not in (OWNER, *LOGIN_ROLES)
            or privilege not in ("CREATE", "TEMPORARY", "CONNECT")
            or grantable is not False
        ):
            raise ValueError("Unexpected baseline database privilege")
        cur.execute(
            sql.SQL("GRANT {} ON DATABASE {} TO {}").format(
                sql.SQL(privilege), sql.Identifier(database), sql.Identifier(role)
            )
        )
    # Resolve every function identity through PostgreSQL before using its
    # server-generated, quoted regprocedure spelling as SQL syntax.
    cur.execute(
        "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='pg_catalog'"
    )
    functions = {row[0] for row in cur.fetchall()}
    for function in sorted(functions):
        cur.execute(
            sql.SQL("REVOKE ALL ON FUNCTION {} FROM PUBLIC").format(sql.SQL(function))
        )
    for function, role, privilege, grantable in value["functions"]:
        if (
            function not in functions
            or role
            not in (
                "PUBLIC",
                "pg_monitor",
                "pg_read_all_stats",
                *LOGIN_ROLES,
                *FUNCTION_ROLES,
            )
            or privilege != "EXECUTE"
            or grantable is not False
        ):
            raise ValueError("Unexpected baseline built-in function privilege")
        role_sql = sql.SQL("PUBLIC") if role == "PUBLIC" else sql.Identifier(role)
        cur.execute(
            sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                sql.SQL(function), role_sql
            )
        )


def provision_empty(
    cur: cursor, *, database: str, passwords: InstallPasswords, profile: str = "empty"
) -> None:
    """Prepare roles/grants only for explicit fresh installation or isolated restore.

    Refuses all existing application objects and roles. It does not create schema
    objects or installation metadata; callers must finish and verify their task.
    """
    contract(profile=profile)
    secrets = passwords.validated()
    _authority(cur, database)
    _require_empty(cur)
    _roles(cur, secrets)
    cur.execute("SHOW search_path")
    previous = cur.fetchone()
    if previous is None:
        raise RuntimeError("PostgreSQL did not return its search path")
    cur.execute("SELECT set_config('search_path','pg_catalog',true)")
    _privileges(cur, database, profile=profile)
    cur.execute("SELECT set_config('search_path',%s,true)", (previous[0],))


def install(
    cur: cursor, *, database: str, passwords: InstallPasswords, profile: str = "empty"
) -> bool:
    """Install only into an empty target; return False for a verified repeat.

    Password files are provisioned by the caller before this transaction, so an
    uncertain acknowledgement never causes a second run to rotate credentials.
    On any exception the caller rolls back the entire installation transaction.
    """
    passwords.validated()
    _authority(cur, database)
    version = installed_version(cur)
    if version is not None:
        verify(cur)
        if version == VERSION:
            actual_profile, _ = identify_layout(fingerprint(cur))
            if actual_profile != profile:
                raise ValueError(
                    "Existing database profile differs from the requested installation"
                )
        return False
    provision_empty(cur, database=database, passwords=passwords, profile=profile)
    cur.execute("SHOW search_path")
    previous = cur.fetchone()
    cur.execute("SHOW check_function_bodies")
    checks = cur.fetchone()
    if previous is None or checks is None:
        raise RuntimeError("PostgreSQL did not return installation settings")
    cur.execute("SELECT set_config('search_path','pg_catalog',true)")
    cur.execute("SELECT set_config('check_function_bodies','off',true)")
    cur.execute((BASE / "schema.sql").read_text())
    cur.execute("SELECT set_config('check_function_bodies',%s,true)", (checks[0],))
    cur.execute("SELECT set_config('search_path',%s,true)", (previous[0],))
    if profile != "empty":
        from .fixtures import seed

        cur.execute((BASE / "synthetic-grants.sql").read_text())
        seed(cur)
    expected = contract(profile=profile)
    require_contract(fingerprint(cur), expected)
    cur.execute(
        "INSERT INTO evidence_pipeline.installation(singleton,version,artifacts,signature) VALUES(true,%s,%s,%s)",
        (VERSION, Json(artifacts()), Json(expected)),
    )
    cur.execute(
        sql.SQL("COMMENT ON DATABASE {} IS %s").format(sql.Identifier(database)),
        (json.dumps(annotation(profile), sort_keys=True),),
    )
    upgrade(cur, database=database)
    return True
