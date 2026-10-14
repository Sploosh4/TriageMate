"""Role-specific connections; callers retain transaction and close ownership."""

from dataclasses import dataclass
from pathlib import Path

import psycopg2
from psycopg2.extensions import connection

from .target import DatabaseTarget, load_target
from .credentials import read_credentials

OWNER = "tm_mock_owner"
READER = "tm_mock_reader"


@dataclass(frozen=True)
class LocalDatabase:
    """An existing configured database, deliberately without lifecycle methods."""

    target: DatabaseTarget

    @property
    def TARGET(self) -> DatabaseTarget:
        return self.target

    @property
    def WORK(self) -> Path:
        return self.target.work

    @property
    def CREDENTIALS(self) -> Path:
        return self.target.credential_directory

    @property
    def DB(self) -> str:
        return self.target.database

    @property
    def PORT(self) -> int:
        return self.target.port

    @property
    def OWNER(self) -> str:
        return OWNER

    def connect(self, database: str | None = None, reader: bool = False) -> connection:
        credential = read_credentials(
            self.CREDENTIALS / "credentials.json", frozenset({"owner", "reader"})
        )
        return psycopg2.connect(
            host=self.target.host,
            port=self.target.port,
            dbname=self.target.database if database is None else database,
            user=READER if reader else OWNER,
            password=credential["reader" if reader else "owner"],
            connect_timeout=5,
            options="-c search_path=pg_catalog,evidence,mock_support -c timezone=UTC",
        )


def local_database() -> LocalDatabase:
    """Resolve an existing target without starting services or reading credentials."""
    return LocalDatabase(load_target())


def connect_pipeline() -> connection:
    """Connect as the constrained pipeline writer; never install or elevate it."""
    target = load_target()
    path = target.credential_directory / "pipeline-writer.json"
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("Unsafe writer credential file")
    return psycopg2.connect(
        host=target.host,
        port=target.port,
        dbname=target.database,
        user="tm_pipeline_writer",
        password=read_credentials(path, frozenset({"password"}))["password"],
        connect_timeout=5,
        options="-c search_path=pg_catalog,evidence,evidence_pipeline -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=10000",
    )


def connect_query_reader(target: DatabaseTarget, credential_file: Path) -> connection:
    """Asynchronous analyst queries retain their restricted role and budgets."""
    return psycopg2.connect(
        host=target.host,
        port=target.port,
        dbname=target.database,
        user=READER,
        password=read_credentials(credential_file, frozenset({"owner", "reader"}))[
            "reader"
        ],
        async_=True,
        application_name="triagemate-ui-query",
        options="-c search_path=pg_catalog,evidence,mock_support -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=20000 -c work_mem=32MB",
    )


def connect_epss_importer(target: DatabaseTarget, credential_file: Path) -> connection:
    """Offline EPSS ingestion cannot acquire owner or pipeline-writer authority."""
    return psycopg2.connect(
        host=target.host,
        port=target.port,
        dbname=target.database,
        user="tm_epss_importer",
        password=read_credentials(credential_file, frozenset({"password"}))["password"],
        connect_timeout=5,
        options="-c search_path=pg_catalog -c timezone=UTC -c statement_timeout=20000 -c lock_timeout=20000",
    )
