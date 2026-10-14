"""Read-only, OID-independent PostgreSQL schema and authority fingerprints.

Fingerprints describe definitions and effective grants, never evidence rows or
passwords. Callers own the transaction and must compare against a trusted contract;
a fingerprint collected from the database under examination is not a baseline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from psycopg2.extensions import TRANSACTION_STATUS_INERROR, cursor

# Include unexpected non-system namespaces so additional objects cannot disappear
# from verification simply because the application never expected their schema.
_NAMESPACE = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"

_QUERIES = {
    "schemas": f"""
        SELECT n.nspname, pg_get_userbyid(n.nspowner)
        FROM pg_namespace n WHERE {_NAMESPACE}
    """,
    "relations": f"""
        SELECT n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner),
               c.relpersistence, c.relrowsecurity, c.relforcerowsecurity,
               c.relreplident, c.relispartition, c.reloptions,
               am.amname, t.spcname,
               CASE WHEN c.relispartition THEN pg_get_expr(c.relpartbound,c.oid) END
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_am am ON am.oid=c.relam
        LEFT JOIN pg_tablespace t ON t.oid=c.reltablespace
        WHERE {_NAMESPACE}
    """,
    "columns": f"""
        SELECT n.nspname, c.relname,
               row_number() OVER (PARTITION BY c.oid ORDER BY a.attnum),
               a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull,
               a.attidentity, a.attgenerated, a.attstorage, a.attcompression,
               a.attstattarget, a.attoptions, a.attfdwoptions,
               co.collname, cn.nspname, pg_get_expr(d.adbin,d.adrelid)
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
        LEFT JOIN pg_collation co ON co.oid=a.attcollation
        LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
        WHERE {_NAMESPACE} AND a.attnum>0 AND NOT a.attisdropped
    """,
    "constraints": f"""
        SELECT n.nspname, con.conrelid::regclass::text, con.conname,
               con.contype, con.condeferrable, con.condeferred, con.convalidated,
               con.connoinherit, pg_get_constraintdef(con.oid,false)
        FROM pg_constraint con JOIN pg_namespace n ON n.oid=con.connamespace
        WHERE {_NAMESPACE}
    """,
    "indexes": f"""
        SELECT n.nspname, c.relname, pg_get_indexdef(i.indexrelid),
               i.indisvalid, i.indisready, i.indislive, i.indisreplident,
               i.indisclustered
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "functions": f"""
        SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
               pg_get_userbyid(p.proowner), pg_get_functiondef(p.oid),
               p.proleakproof, p.proparallel, p.proconfig
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE {_NAMESPACE} AND p.prokind <> 'a'
    """,
    "aggregates": f"""
        SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
               pg_get_userbyid(p.proowner), a.aggkind, a.aggnumdirectargs,
               a.aggtransfn::regprocedure::text, a.aggfinalfn::regprocedure::text,
               a.aggcombinefn::regprocedure::text,
               a.aggserialfn::regprocedure::text,
               a.aggdeserialfn::regprocedure::text,
               a.aggmtransfn::regprocedure::text,
               a.aggminvtransfn::regprocedure::text,
               a.aggmfinalfn::regprocedure::text,
               a.aggfinalextra,a.aggmfinalextra,a.aggfinalmodify,a.aggmfinalmodify,
               a.aggsortop::regoperator::text,a.aggtranstype::regtype::text,
               a.aggtransspace,a.aggmtranstype::regtype::text,a.aggmtransspace,
               a.agginitval,a.aggminitval
        FROM pg_aggregate a JOIN pg_proc p ON p.oid=a.aggfnoid
        JOIN pg_namespace n ON n.oid=p.pronamespace WHERE {_NAMESPACE}
    """,
    "triggers": f"""
        SELECT n.nspname, c.relname,
               CASE WHEN t.tgisinternal THEN con.conname ELSE t.tgname END,
               t.tgisinternal, t.tgenabled, t.tgtype,
               t.tgfoid::regprocedure::text, t.tgdeferrable, t.tginitdeferred,
               CASE WHEN t.tgisinternal THEN NULL ELSE pg_get_triggerdef(t.oid,false) END
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_constraint con ON con.oid=t.tgconstraint
        WHERE {_NAMESPACE}
    """,
    "rules": f"""
        SELECT n.nspname,c.relname,r.rulename,r.ev_enabled,pg_get_ruledef(r.oid,false)
        FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "policies": f"""
        SELECT n.nspname,c.relname,p.polname,p.polcmd,p.polpermissive,
               ARRAY(SELECT CASE WHEN role=0 THEN 'PUBLIC' ELSE pg_get_userbyid(role) END
                     FROM unnest(p.polroles) role ORDER BY 1),
               pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)
        FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "types": f"""
        SELECT n.nspname,t.typname,t.typtype,pg_get_userbyid(t.typowner),
               t.typcategory,t.typispreferred,t.typnotnull,
               t.typbasetype::regtype::text,t.typtypmod,t.typdefault,
               t.typinput::regprocedure::text,t.typoutput::regprocedure::text,
               t.typreceive::regprocedure::text,t.typsend::regprocedure::text,
               t.typmodin::regprocedure::text,t.typmodout::regprocedure::text,
               t.typanalyze::regprocedure::text,t.typalign,t.typstorage
        FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
        WHERE {_NAMESPACE}
    """,
    "enums": f"""
        SELECT n.nspname,t.typname,e.enumsortorder,e.enumlabel
        FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid
        JOIN pg_namespace n ON n.oid=t.typnamespace WHERE {_NAMESPACE}
    """,
    "sequences": f"""
        SELECT n.nspname,c.relname,s.seqtypid::regtype::text,s.seqstart,
               s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle
        FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "inheritance": f"""
        SELECT c.oid::regclass::text, i.inhparent::regclass::text,
               i.inhseqno,i.inhdetachpending
        FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "partitions": f"""
        SELECT c.oid::regclass::text, pg_get_partkeydef(c.oid)
        FROM pg_partitioned_table p JOIN pg_class c ON c.oid=p.partrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE {_NAMESPACE}
    """,
    "default_acl_objects": """
        SELECT pg_get_userbyid(d.defaclrole),coalesce(n.nspname,''),d.defaclobjtype
        FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
    """,
    "foreign_tables": f"""
        SELECT c.oid::regclass::text,s.srvname,f.ftoptions
        FROM pg_foreign_table f JOIN pg_class c ON c.oid=f.ftrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_foreign_server s ON s.oid=f.ftserver WHERE {_NAMESPACE}
    """,
    "foreign_servers": """
        SELECT s.srvname,pg_get_userbyid(s.srvowner),w.fdwname,s.srvtype,s.srvversion
        FROM pg_foreign_server s JOIN pg_foreign_data_wrapper w ON w.oid=s.srvfdw
    """,
    "foreign_wrappers": """
        SELECT fdwname,pg_get_userbyid(fdwowner),fdwhandler::regprocedure::text,
               fdwvalidator::regprocedure::text FROM pg_foreign_data_wrapper
    """,
    "extensions": """
        SELECT e.extname,e.extversion,n.nspname,pg_get_userbyid(e.extowner)
        FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
    """,
    "roles": """
        SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,
               rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil::text,
               ARRAY(SELECT x FROM unnest(rolconfig) x ORDER BY x)
        FROM pg_roles WHERE left(rolname,3)='tm_'
    """,
    "memberships": """
        SELECT parent.rolname,child.rolname,pg_get_userbyid(m.grantor),
               m.admin_option,m.inherit_option,m.set_option
        FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid
        JOIN pg_roles child ON child.oid=m.member
        WHERE left(parent.rolname,3)='tm_' OR left(child.rolname,3)='tm_'
    """,
    "role_settings": """
        SELECT CASE WHEN s.setdatabase=0 THEN '*' ELSE 'current_database' END,
               CASE WHEN s.setrole=0 THEN '*' ELSE pg_get_userbyid(s.setrole) END,
               ARRAY(SELECT x FROM unnest(s.setconfig) x ORDER BY x)
        FROM pg_db_role_setting s
        WHERE s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database())
           OR (s.setdatabase=0 AND left(pg_get_userbyid(s.setrole),3)='tm_')
    """,
    "default_acl": """
        SELECT pg_get_userbyid(d.defaclrole),coalesce(n.nspname,''),d.defaclobjtype,
               pg_get_userbyid(a.grantor),
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type,a.is_grantable
        FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
        CROSS JOIN LATERAL aclexplode(d.defaclacl) a
    """,
    "object_acl": f"""
        WITH objects(kind,identity,acl) AS (
          SELECT 'schema',n.nspname,coalesce(n.nspacl,acldefault('n',n.nspowner))
            FROM pg_namespace n WHERE {_NAMESPACE}
          UNION ALL
          SELECT 'relation',c.oid::regclass::text,
                 coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE {_NAMESPACE} AND c.relkind IN ('r','v','m','S','f','p')
          UNION ALL
          SELECT 'column',c.oid::regclass::text||'.'||quote_ident(a.attname),a.attacl
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE {_NAMESPACE} AND a.attnum>0 AND NOT a.attisdropped
          UNION ALL
          SELECT 'function',p.oid::regprocedure::text,
                 coalesce(p.proacl,acldefault('f',p.proowner))
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE {_NAMESPACE} OR n.nspname='pg_catalog'
          UNION ALL
          SELECT 'type',t.oid::regtype::text,coalesce(t.typacl,acldefault('T',t.typowner))
            FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
            WHERE {_NAMESPACE}
        )
        SELECT o.kind,o.identity,pg_get_userbyid(a.grantor),
               CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type,a.is_grantable
        FROM objects o CROSS JOIN LATERAL aclexplode(o.acl) a
    """,
    # CI and local PostgreSQL use different administrative database owners.
    # Only the actual database owner's identity is normalized here; application
    # object owners, tm_* roles and all other database grantees remain exact.
    "database_acl": """
        SELECT CASE WHEN a.grantor=d.datdba THEN '$database_owner' ELSE pg_get_userbyid(a.grantor) END,
               CASE WHEN a.grantee=0 THEN 'PUBLIC' WHEN a.grantee=d.datdba THEN '$database_owner'
                    ELSE pg_get_userbyid(a.grantee) END,
               a.privilege_type,a.is_grantable
        FROM pg_database d CROSS JOIN LATERAL
             aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a
        WHERE d.datname=current_database()
    """,
}


def fingerprint(cur: cursor) -> dict[str, str]:
    """Hash catalogue rows in a stable search path, restoring caller settings.

    Requires a live transaction (autocommit is intentionally unsupported).
    No commit, rollback, DDL or installation-metadata writes are performed.
    """
    if cur.connection.autocommit:
        raise ValueError("Schema verification requires a caller-owned transaction")
    cur.execute("SHOW search_path")
    previous = cur.fetchone()
    if previous is None:
        raise RuntimeError("PostgreSQL did not return its search path")
    cur.execute("SELECT set_config('search_path','pg_catalog',true)")
    result = {}
    try:
        for name, query in _QUERIES.items():
            cur.execute(query)
            rows = sorted(
                json.dumps(row, separators=(",", ":")) for row in cur.fetchall()
            )
            result[name] = hashlib.sha256("\n".join(rows).encode()).hexdigest()
    finally:
        # If SQL failed, the caller must roll back its own transaction; attempting
        # another statement in an aborted transaction would mask that exception.
        if cur.connection.get_transaction_status() != TRANSACTION_STATUS_INERROR:
            cur.execute("SELECT set_config('search_path',%s,true)", (previous[0],))
    return result


def require_contract(actual: Mapping[str, str], expected: Mapping[str, str]) -> None:
    """Reject any missing, unexpected or changed catalogue category."""
    changed = sorted(
        name
        for name in actual.keys() | expected.keys()
        if actual.get(name) != expected.get(name)
    )
    if changed:
        raise ValueError("Database schema/authority differs: " + ", ".join(changed))
