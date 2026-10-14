"""Keep fact parsing and assessment independent of provider I/O and persistence."""

import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# These modules provide source contracts, exact encoding and bounded local spill
# storage. They do not install application schemas, collect or commit evidence.
FOUNDATIONS = {
    "standalone.evidence_pipeline.contracts",
    "standalone.evidence_pipeline.epss_route",
    "standalone.evidence_pipeline.file_payload",
    "standalone.evidence_pipeline.json_stream",
    "standalone.evidence_pipeline.temporary_index",
    "standalone.evidence_pipeline.text_bytes",
    "standalone.evidence_pipeline.verification_spool",
    "standalone.evidence_pipeline.source_json",
}
IO_PACKAGES = {
    "psycopg",
    "psycopg2",
    "asyncpg",
    "requests",
    "httpx",
    "socket",
    "subprocess",
}


@pytest.mark.parametrize("package", ["parsing", "assessment"])
def test_fact_layers_do_not_import_collectors_or_application_database(package):
    violations = []
    directory = ROOT / "standalone/evidence_pipeline" / package
    assert directory.is_dir()
    for path in directory.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                name = (
                    importlib.util.resolve_name(
                        "." * node.level + (node.module or ""),
                        "standalone.evidence_pipeline." + package,
                    )
                    if node.level
                    else node.module
                )
                names = [name or ""]
            else:
                continue
            for name in names:
                forbidden_io = name.split(".")[0] in IO_PACKAGES or name.startswith(
                    "urllib.request"
                )
                application_dependency = name.startswith(
                    ("backend.", "standalone.", "ui_engine.")
                )
                allowed = (
                    name == "standalone.evidence_pipeline.parsing"
                    or name.startswith("standalone.evidence_pipeline.parsing.")
                    or (
                        package == "assessment"
                        and (
                            name.startswith("standalone.evidence_pipeline.assessment.")
                            or name == "standalone.windows_inventory.manifest"
                        )
                    )
                    or name in FOUNDATIONS
                )
                if forbidden_io or (application_dependency and not allowed):
                    violations.append(f"{path.name}:{node.lineno}: {name}")
    assert not violations, f"{package} dependency crosses its boundary:\n" + "\n".join(
        violations
    )
