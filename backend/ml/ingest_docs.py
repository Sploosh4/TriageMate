"""
CLI script to ingest documents into the LanceDB vector store.

Usage:
    python -m ml.ingest_docs --file path/to/doc.md --hostname asset.wa.gov.au
    python -m ml.ingest_docs --dir ./docs --hostname prd-app01.wa.gov.au
    python -m ml.ingest_docs --file app.properties --document-type app_config
    python -m ml.ingest_docs --reset --dir ./cmdb_export
"""

import argparse
import json
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("ingest_docs")

# Size limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
WARN_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

# Supported document types by file extension
DOC_TYPE_MAP = {
    ".md": "runbook",
    ".json": "cmdb_export",
    ".txt": "config_file",
    ".yaml": "config_file",
    ".yml": "config_file",
    ".xml": "config_file",
    ".properties": "config_file",
    ".cfg": "config_file",
    ".conf": "config_file",
}


def resolve_path(path: str, allowed_base: Path) -> Path:
    """Resolve a file path and verify it's within the allowed base directory.

    Prevents path traversal attacks.
    """
    p = Path(path).resolve()
    if allowed_base not in p.parents and p != allowed_base:
        raise ValueError(
            f"Path {path} resolves to {p} which is outside the allowed directory {allowed_base}"
        )
    return p


def validate_file(file_path: Path):
    """Validate file size and basic content."""
    size = file_path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File {file_path} is {size} bytes (max {MAX_FILE_SIZE})")
    if size > WARN_FILE_SIZE:
        logger.warning(f"Large file: {file_path} ({size} bytes)")


def detect_document_type(file_path: Path) -> str:
    """Detect document type from file extension."""
    return DOC_TYPE_MAP.get(file_path.suffix.lower(), "unknown")


def validate_content(file_path: Path, doc_type: str):
    """Validate file content matches the expected type."""
    if doc_type == "cmdb_export":
        try:
            json.loads(file_path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(
                f"File {file_path} is labeled as cmdb_export but is not valid JSON: {e}"
            )


def chunk_document(text: str, max_chars: int = 2000, overlap: int = 200) -> list[str]:
    """Split a document into chunks suitable for embedding.

    For Markdown: splits on ## headers first, then recursively splits
    sections exceeding max_chars using a sliding window.
    For plain text: uses a sliding window with overlap.
    """
    if len(text) <= max_chars:
        return [text]

    # Try markdown header splitting first
    lines = text.split("\n")
    sections = []
    current_section = []
    for line in lines:
        if line.startswith("## ") and current_section:
            sections.append("\n".join(current_section))
            current_section = [line]
        else:
            current_section.append(line)
    if current_section:
        sections.append("\n".join(current_section))

    # If header splitting produced usable chunks, use those
    if len(sections) > 1:
        result = []
        for section in sections:
            if len(section) <= max_chars:
                result.append(section)
            else:
                result.extend(_sliding_window_chunks(section, max_chars, overlap))
        return result

    # Plain text: sliding window
    return _sliding_window_chunks(text, max_chars, overlap)


def _sliding_window_chunks(text: str, max_chars: int, overlap: int) -> list[str]:
    """Split text into chunks using a sliding window with overlap."""
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunk = text[start:end]
        chunks.append(chunk)
        if end == len(text):
            break
        start = end - overlap
    return chunks


def ingest_file(
    file_path: Path | str,
    hostname: str = "",
    document_type: str = "",
    reset: bool = False,
):
    """Ingest a single file into the vector store."""
    file_path = Path(file_path)
    validate_file(file_path)
    doc_type = document_type or detect_document_type(file_path)
    validate_content(file_path, doc_type)

    text = file_path.read_text(encoding="utf-8")
    chunks = chunk_document(text)

    from ml.vector_store import add_documents, clear_documents
    from ml.vector_store import init_vector_store

    init_vector_store()

    if reset:
        clear_documents()
        logger.info("Vector store cleared")

    docs = [
        {
            "text": chunk,
            "hostname": hostname,
            "document_type": doc_type,
            "source": file_path.name,
        }
        for chunk in chunks
    ]

    count = add_documents(docs)
    logger.info(f"Ingested {count} chunk(s) from {file_path} ({doc_type})")
    return count


def ingest_directory(dir_path: Path | str, hostname: str = "", reset: bool = False):
    """Recursively ingest all supported files from a directory."""
    dir_path = Path(dir_path)
    total = 0
    for fpath in sorted(dir_path.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in DOC_TYPE_MAP:
            continue
        try:
            total += ingest_file(fpath, hostname=hostname, reset=(reset and total == 0))
        except Exception as e:
            logger.warning(f"Skipping {fpath}: {e}")
    return total


def main():
    parser = argparse.ArgumentParser(
        description="Ingest documents into TriageMate RAG vector store"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", type=str, help="Single file to ingest")
    group.add_argument("--dir", type=str, help="Directory to scan recursively")
    parser.add_argument(
        "--hostname",
        type=str,
        default="",
        help="Associate documents with this hostname",
    )
    parser.add_argument(
        "--document-type",
        type=str,
        default="",
        help="Override document type (e.g., runbook, cmdb_export, app_config)",
    )
    parser.add_argument(
        "--reset", action="store_true", help="Clear existing documents before ingesting"
    )

    args = parser.parse_args()

    allowed_base = Path(__file__).parent.parent.parent.resolve()

    if args.dir:
        dir_path = resolve_path(args.dir, allowed_base)
        if not dir_path.is_dir():
            logger.error(f"Directory not found: {dir_path}")
            sys.exit(1)
        count = ingest_directory(dir_path, hostname=args.hostname, reset=args.reset)
        logger.info(f"Total: {count} chunk(s) ingested from {dir_path}")

    elif args.file:
        file_path = resolve_path(args.file, allowed_base)
        if not file_path.is_file():
            logger.error(f"File not found: {file_path}")
            sys.exit(1)
        count = ingest_file(
            file_path,
            hostname=args.hostname,
            document_type=args.document_type,
            reset=args.reset,
        )
        logger.info(f"Total: {count} chunk(s) ingested from {file_path}")


if __name__ == "__main__":
    main()
