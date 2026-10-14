"""Exact adoption companion for the retained runner's archived public schema.

This is not a fresh-install profile or a restored product capability. Contracts
come from independent synthetic construction; no live schema is learned here.
"""

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path

from psycopg2 import sql
from psycopg2.extensions import cursor

BASE = Path(__file__).parent
PREFIX = "retained-runner/"
FILES = (
    "predecessor-contract.json",
    "current-contract.json",
    "construction.json",
    "authority.json",
    "restore-grants.sql",
)
ROLES = (
    "triagemate_retention_approver",
    "triagemate_retention_executor",
    "triagemate_test_application",
)


def contract(*, predecessor: bool = False) -> dict[str, str]:
    name = "predecessor-contract.json" if predecessor else "current-contract.json"
    value: dict[str, str] = json.loads((BASE / name).read_text())
    if not value or any(len(digest) != 64 for digest in value.values()):
        raise ValueError("Invalid retained runner contract")
    return value


def matches(actual: Mapping[str, str]) -> bool:
    return any(actual == contract(predecessor=old) for old in (False, True))


def artifacts() -> dict[str, str]:
    return {
        PREFIX + name: hashlib.sha256((BASE / name).read_bytes()).hexdigest()
        for name in FILES
    }


def predecessor_signature() -> str:
    value: str = json.loads((BASE / "construction.json").read_text())[
        "predecessor_signature_sha256"
    ]
    return value


def authority(cur: cursor) -> dict[str, object]:
    """Cover legacy role attributes/membership beyond the baseline tm_* roles."""
    cur.execute(
        "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,"
        "rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil::text,"
        "ARRAY(SELECT x FROM unnest(rolconfig) x ORDER BY x) "
        "FROM pg_roles WHERE rolname=ANY(%s) ORDER BY rolname",
        (list(ROLES),),
    )
    roles = [list(row) for row in cur.fetchall()]
    cur.execute(
        "SELECT parent.rolname,child.rolname,pg_get_userbyid(m.grantor),"
        "m.admin_option,m.inherit_option,m.set_option "
        "FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid "
        "JOIN pg_roles child ON child.oid=m.member "
        "WHERE parent.rolname=ANY(%s) OR child.rolname=ANY(%s) ORDER BY 1,2,3",
        (list(ROLES), list(ROLES)),
    )
    memberships = [list(row) for row in cur.fetchall()]
    # Include per-role settings for every database, not just this database.
    cur.execute(
        "SELECT s.setdatabase::text,r.rolname,"
        "ARRAY(SELECT x FROM unnest(s.setconfig) x ORDER BY x) "
        "FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole "
        "WHERE r.rolname=ANY(%s) ORDER BY 1,2",
        (list(ROLES),),
    )
    return {
        "roles": roles,
        "memberships": memberships,
        "settings": [list(row) for row in cur.fetchall()],
    }


def verify(cur: cursor) -> None:
    if authority(cur) != json.loads((BASE / "authority.json").read_text()):
        raise ValueError("Retained runner legacy role authority differs")
    cur.execute("SELECT version_num FROM public.alembic_version ORDER BY version_num")
    if cur.fetchall() != [("058",)]:
        raise ValueError("Retained runner public revision differs")


def prepare_isolated_restore(cur: cursor) -> None:
    """Prepare only after the caller establishes a different empty cluster.

    Unknown public contents or preexisting legacy identities are rejected;
    any failure rolls back with the caller's transaction. Controlled full
    pg_dump archives retain initdb's public namespace and restore its owner/ACL.
    """
    cur.execute("SELECT rolname FROM pg_roles WHERE rolname=ANY(%s)", (list(ROLES),))
    if cur.fetchall():
        raise ValueError("Retained runner restore roles already exist")
    cur.execute(
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()"
    )
    if cur.fetchone() != ("triagemate",):
        raise ValueError("Retained runner restore requires its exact database owner")
    cur.execute(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'"
    )
    if cur.fetchone() != ("pg_database_owner",):
        raise ValueError(
            "Retained runner restore requires an untouched empty public schema"
        )
    cur.execute(
        "SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace "
        "UNION ALL SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace "
        "UNION ALL SELECT 1 FROM pg_type WHERE typnamespace='public'::regnamespace"
    )
    if cur.fetchone():
        raise ValueError("Retained runner restore requires an empty public schema")
    for role in ROLES:
        cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
    # Legacy grants were issued by the provisioning administrator, not the
    # application owner. SET LOCAL ROLE is transaction-scoped and restored.
    cur.execute("SET LOCAL ROLE triagemate")
    cur.execute((BASE / "restore-grants.sql").read_text())
    cur.execute("SET LOCAL ROLE tm_mock_owner")
