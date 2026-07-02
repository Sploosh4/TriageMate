"""
LanceDB embedded vector store for RAG document retrieval.

Stores internal agency documentation as chunked embeddings.
Runs in-process within the FastAPI application — no server required.
Reads are lock-free (LanceDB uses immutable file manifests).
Writes are guarded by a threading.Lock for safety.
"""

import logging
import threading
from pathlib import Path
from typing import Optional

import lancedb
import pyarrow as pa
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("triagemate.vector_store")

DB_PATH = Path(__file__).parent.parent / "data" / "lancedb"
TABLE_NAME = "asset_documentation"
EMBEDDING_DIM = 384
MAX_RAG_CHARS = 5000

_embedder = None
_db = None
_write_lock = threading.Lock()


_SEED_DOCUMENTS = [
    {
        "hostname": "per-PRD-MOVEIT-WEB01.health.wa.gov.au",
        "document_type": "cmdb_record",
        "source": "CMDB Export",
        "text": (
            "Asset: per-PRD-MOVEIT-WEB01.health.wa.gov.au. "
            "Software: Progress MOVEit Transfer 2023.0.0 build 15.0.0.185. "
            "Role: Managed File Transfer Server for inter-hospital HIE. "
            "Interface: Internet-facing HTTPS on TCP 443, no VPN required. "
            "No WAF detected. No MFA on admin interface. "
            "Patch: Available (2023.0.2+). Not applied. "
            "Data Classification: OFFICIAL Sensitive. Network Zone: DMZ-Health-External. "
            "Dependent assets: per-PRD-SQL-CLUSTER01, per-PRD-FILE-SAN01."
        ),
    },
    {
        "hostname": "per-PRD-CITRIX-ADC01.transport.wa.gov.au",
        "document_type": "cmdb_record",
        "source": "CMDB Export",
        "text": (
            "Asset: per-PRD-CITRIX-ADC01.transport.wa.gov.au. "
            "Software: Citrix NetScaler ADC VPX 13.1-49.13. "
            "Role: Perimeter remote access gateway for Dept of Transport. "
            "Interface: Internet-facing HTTPS on TCP 443 (VIP). "
            "Build 49.13 is vulnerable. Fix in build 49.15+. "
            "20+ downstream application targets (TEMIS, DVS, Marine Safety). "
            "Data Classification: OFFICIAL Sensitive. Network Zone: DMZ-Transport-External."
        ),
    },
    {
        "hostname": "per-PRD-PRINT-SVR05.education.wa.edu.au",
        "document_type": "cmdb_record",
        "source": "CMDB Export",
        "text": (
            "Asset: per-PRD-PRINT-SVR05.education.wa.edu.au. "
            "Software: PaperCut MF 22.0.6. "
            "Service Account: DOMAIN_EDU\\svc-papercut-prd (local administrator). "
            "Interface: Internal only (TCP 9191, 9192, 9164). "
            "28 downstream endpoints across 14 school campuses. "
            "Flat education network architecture. Data Classification: OFFICIAL."
        ),
    },
    {
        "hostname": "per-PRD-RMM-GW01.sharedservices.wa.gov.au",
        "document_type": "cmdb_record",
        "source": "CMDB Export",
        "text": (
            "Asset: per-PRD-RMM-GW01.sharedservices.wa.gov.au. "
            "Software: ConnectWise ScreenConnect 23.9.7.8804. "
            "Role: RMM gateway for Shared Services Centre. "
            "Interface: Isolated management VLAN 48 (TCP 8040, 8041). "
            "14 downstream endpoints across 5 network zones "
            "(DLGSC, DWER, DPLH, Finance, DBCA). "
            "Data Classification: OFFICIAL Sensitive. Inbound access restricted."
        ),
    },
    {
        "hostname": "per-PRD-FILE-STORE02.communities.wa.gov.au",
        "document_type": "gpo_report",
        "source": "Group Policy Management Console",
        "text": (
            "Host: per-PRD-FILE-STORE02.communities.wa.gov.au. "
            "Microsoft Defender ASR Rule: GUID D4F940AB-401B-4EFC-AADC-AD5F3C50688A "
            "(Block Office applications from creating child processes). "
            "GPO: Communities-Endpoint-ASR-v2. Applied: September 2023. "
            "CMDB record 2026-03-07: GPO replication status shows "
            "LastProcessed=FAILURE. Error code 0x80070005. "
            "ASR rule enforcement status on this endpoint is UNCERTAIN. "
            "Mitigation for CVE-2023-36884 may or may not be active."
        ),
    },
    {
        "hostname": "per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au",
        "document_type": "change_record",
        "source": "Change Management System",
        "text": (
            "Change ID: CM-2023-10287. Date: 19-Oct-2023. "
            "Description: Emergency upgrade of Confluence Data Center "
            "from 8.5.1 to 8.5.2 to remediate CVE-2023-22515 on "
            "per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au. "
            "Status: COMPLETED. Implementer: J. Morrison. "
            "TARGET HOST FIELD: per-PRD-WIKI-CORE02 (staging/DR instance). "
            "DNS: per-PRD-WIKI-CORE01 = 10.185.42.9. "
            "DNS: per-PRD-WIKI-CORE02 = 10.185.42.10. "
            "Scanner continues to fingerprint Confluence 8.5.1 on "
            "per-PRD-WIKI-CORE01. Hostname alias ambiguity."
        ),
    },
    {
        "hostname": "per-PRD-ITSM-TOOL01.finance.wa.gov.au",
        "document_type": "application_config",
        "source": "application.properties export",
        "text": (
            "Host: per-PRD-ITSM-TOOL01.finance.wa.gov.au. "
            "Software: ManageEngine ServiceDesk Plus 14.0 build 13000. "
            "SAML SSO Configuration: saml.sso.enabled=false. "
            "Authentication: LDAP only. "
            "Endpoint /SamlResponseServlet: Not active (returns HTTP 404). "
            "SAML libraries present in installed JAR files but code path "
            "is unreachable while saml.sso.enabled=false. "
            "Attack surface for CVE-2022-47966: ELIMINATED under current config. "
            "Risk: If SAML is ever enabled, vulnerability reactivates."
        ),
    },
    {
        "hostname": "__generic__",
        "document_type": "security_baseline",
        "source": "WA Government Security Baseline",
        "text": (
            "WA Government Windows Server Security Baseline. "
            "Microsoft Defender for Endpoint: Required on all domain-joined servers. "
            "ASR Rules: Block Office child processes (D4F940AB-401B-4EFC-AADC-AD5F3C50688A), "
            "Block Win32 API calls from Office macros (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B). "
            "SMB: SMBv1 disabled. SMB signing: Required. SMB encryption: Optional. "
            "RDP: Network Level Authentication required. "
            "Patch cycle: Monthly via WSUS/SCCM. "
            "Audit policy: Advanced audit logging enabled for logon/logoff, object access."
        ),
    },
    {
        "hostname": "__generic__",
        "document_type": "iam_policy",
        "source": "WA Government Identity Policy",
        "text": (
            "WA Government Service Account Policy. "
            "Service accounts: Should not be granted interactive logon rights. "
            "Managed Service Accounts (gMSA) preferred over standard user accounts. "
            "Privileged access workstations (PAWs) required for admin access to Tier 0 assets. "
            "Multi-factor authentication: Required for all internet-facing admin interfaces. "
            "Default domain admin accounts: Renamed, with honeypot accounts deployed. "
            "Kerberos: AES256 encryption preferred. RC4/HMAC-MD5 disabled where compatible."
        ),
    },
]


def _get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
    return _embedder


def _get_db() -> lancedb.DBConnection:
    global _db
    if _db is None:
        DB_PATH.mkdir(parents=True, exist_ok=True)
        _db = lancedb.connect(str(DB_PATH))
    return _db


def init_vector_store() -> lancedb.DBConnection:
    """Initialize the LanceDB database and create the table if it doesn't exist."""
    db = _get_db()

    schema = pa.schema(
        [
            pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
            pa.field("text", pa.string()),
            pa.field("hostname", pa.string()),
            pa.field("document_type", pa.string()),
            pa.field("source", pa.string()),
        ]
    )

    if TABLE_NAME not in db.list_tables().tables:
        db.create_table(TABLE_NAME, schema=schema, exist_ok=True)

    table = db.open_table(TABLE_NAME)
    with _write_lock:
        try:
            table.create_fts_index("text", replace=True)
        except Exception as e:
            logger.warning("FTS index creation skipped: %s", e)

    return db


def seed_demo_documents(db: Optional[lancedb.DBConnection] = None) -> int:
    """Seed the vector store with known configurations for the 7 demo hosts."""
    if db is None:
        db = _get_db()
    embedder = _get_embedder()
    table = db.open_table(TABLE_NAME)

    texts = [doc["text"] for doc in _SEED_DOCUMENTS]
    vectors = embedder.encode(texts, show_progress_bar=False)

    records = []
    for i, doc in enumerate(_SEED_DOCUMENTS):
        records.append(
            {
                "vector": vectors[i].tolist(),
                "text": doc["text"],
                "hostname": doc["hostname"],
                "document_type": doc["document_type"],
                "source": doc["source"],
            }
        )

    with _write_lock:
        table.add(records)
    return len(records)


def clear_documents(db: Optional[lancedb.DBConnection] = None):
    """Remove all documents from the vector store."""
    if db is None:
        db = _get_db()
    table = db.open_table(TABLE_NAME)
    with _write_lock:
        table.delete("true")


def add_documents(docs: list[dict], db: Optional[lancedb.DBConnection] = None) -> int:
    """Add a batch of documents to the vector store.

    Each dict must have: text, hostname, document_type, source.
    The vector embedding is computed automatically.
    """
    if db is None:
        db = _get_db()
    embedder = _get_embedder()
    table = db.open_table(TABLE_NAME)

    texts = [d["text"] for d in docs]
    vectors = embedder.encode(texts, show_progress_bar=True)

    records = []
    for i, doc in enumerate(docs):
        records.append(
            {
                "vector": vectors[i].tolist(),
                "text": doc["text"],
                "hostname": doc["hostname"],
                "document_type": doc.get("document_type", "unknown"),
                "source": doc.get("source", "manual_ingest"),
            }
        )

    with _write_lock:
        table.add(records)
    return len(records)


def _empty_result(status: str, message: str) -> dict:
    return {"documents": [], "status": status, "rag_context": message}


_rag_cache = {}
_RAG_CACHE_TTL = 60


def query_rag(hostname: str, cwe_class: str = "", top_k: int = 3) -> dict:
    """
    Query the vector store for asset configuration context.

    Results are cached per hostname for _RAG_CACHE_TTL seconds to avoid
    redundant LanceDB lookups for concurrent ingest of different CVEs
    on the same hostname.

    Returns dict with: documents, status, rag_context.
    Status values: STORE_EMPTY, STORE_ERROR, SEARCH_ERROR, NO_MATCHES, RESULTS_FOUND
    """
    cache_key = f"{hostname}::{cwe_class}::{top_k}"
    import time

    now = time.time()
    cached = _rag_cache.get(cache_key)
    if cached and (now - cached["ts"]) < _RAG_CACHE_TTL:
        return cached["result"]

    try:
        db = _get_db()
        if TABLE_NAME not in db.list_tables().tables:
            return _empty_result(
                "STORE_EMPTY",
                "RAG document store has not been populated. "
                "No internal configuration data is available for this asset.",
            )
        table = db.open_table(TABLE_NAME)
    except Exception as e:
        return _empty_result(
            "STORE_ERROR", f"RAG vector store unavailable: {str(e)[:100]}"
        )

    query = (
        f"Security configurations, mitigations, default settings, "
        f"and active hardening parameters for {hostname}"
    )
    if cwe_class:
        query += f" to resolve vulnerability class {cwe_class}"

    try:
        embedder = _get_embedder()
        query_vec = embedder.encode([query], show_progress_bar=False)[0]
        results = table.search(query_vec).limit(top_k).to_list()
        if not results:
            results = table.search(query, query_type="fts").limit(top_k).to_list()
    except Exception:
        try:
            results = table.search(query, query_type="fts").limit(top_k).to_list()
        except Exception as e:
            return _empty_result(
                "SEARCH_ERROR", f"Vector search failed: {str(e)[:100]}"
            )

    if not results:
        result = _empty_result(
            "NO_MATCHES",
            f"No internal documentation found for {hostname}. "
            f"Configuration status is unknown.",
        )
        _rag_cache[cache_key] = {"result": result, "ts": now}
        return result

    rag_text = "\n\n".join(
        f"[{r.get('document_type', 'doc')}] {r['text']}" for r in results
    )

    result = {
        "documents": results,
        "status": "RESULTS_FOUND",
        "rag_context": rag_text[:MAX_RAG_CHARS],
    }
    _rag_cache[cache_key] = {"result": result, "ts": now}
    return result
