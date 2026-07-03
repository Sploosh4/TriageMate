"""
Build CWE hierarchy JSON from MITRE CWE XML.

Downloads https://cwe.mitre.org/data/xml/cwec_latest.xml.zip,
parses <Weakness> elements, extracts ID, Name, Abstraction, and
parent CWE (ChildOf relationships).

Output: backend/data/cwe_hierarchy.json (~900+ entries)

Usage:
    python -m scripts.build_cwe_hierarchy [--download]
"""

import json
import logging
import os
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.build_cwe_hierarchy")

DATA_DIR = Path(__file__).parent.parent / "data"
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_FILE = DATA_DIR / "cwe_hierarchy.json"


def download_zip() -> bytes:
    """Download cwec_latest.xml.zip and return contents as bytes."""
    import urllib.request

    logger.info("Downloading CWE hierarchy from %s", CWE_ZIP_URL)
    req = urllib.request.Request(
        CWE_ZIP_URL, headers={"User-Agent": "TriageMate/0.3.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
        logger.info("Downloaded %d bytes", len(data))
        return data
    except Exception as e:
        logger.error("Failed to download CWE ZIP: %s", e)
        raise


def parse_cwe_xml(xml_path: str) -> dict:
    """Parse cwec.xml and extract Weakness hierarchy.

    Returns {cwe_id: {name, abstraction, parent}, ...}
    """
    logger.info("Parsing CWE XML from %s ...", xml_path)
    tree = ET.parse(xml_path)
    root = tree.getroot()

    weaknesses: dict = {}

    for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
        cwe_id = weakness.get("ID")
        name = weakness.get("Name")
        abstraction = weakness.get("Abstraction")

        if not cwe_id or not name:
            continue

        cwe_key = f"CWE-{cwe_id}"
        entry: dict = {
            "name": name,
            "abstraction": abstraction or "",
            "parent": "",
        }

        related = weakness.find("{http://cwe.mitre.org/cwe-7}Related_Weaknesses")
        if related is not None:
            for rel in related.findall("{http://cwe.mitre.org/cwe-7}Related_Weakness"):
                nature = rel.get("Nature")
                if nature == "ChildOf":
                    parent_id = rel.get("CWE_ID")
                    if parent_id:
                        entry["parent"] = f"CWE-{parent_id}"

        weaknesses[cwe_key] = entry

    logger.info("Parsed %d weakness entries", len(weaknesses))
    return weaknesses


def extract_zip_in_temp(zip_data: bytes) -> str:
    """Extract CWE XML ZIP to a temp directory and return path to XML file."""
    tmp_dir = tempfile.mkdtemp(prefix="cwe_")
    zip_path = os.path.join(tmp_dir, "cwec.zip")
    with open(zip_path, "wb") as f:
        f.write(zip_data)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tmp_dir)
        xml_files = [f for f in zf.namelist() if f.endswith(".xml")]
        if not xml_files:
            raise RuntimeError("No XML found in CWE ZIP")
        return os.path.join(tmp_dir, xml_files[0])


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Build CWE hierarchy JSON")
    parser.add_argument("--download", action="store_true", help="Download CWE XML ZIP")
    args = parser.parse_args()

    if args.download:
        zip_data = download_zip()
        xml_path = extract_zip_in_temp(zip_data)
    else:
        local_path = DATA_DIR / "cwec_latest.xml"
        if local_path.exists():
            xml_path = str(local_path)
        else:
            logger.warning(
                "No local CWE XML found at %s. Use --download to fetch it.", local_path
            )
            zip_data = download_zip()
            xml_path = extract_zip_in_temp(zip_data)

    weaknesses = parse_cwe_xml(xml_path)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(CWE_FILE, "w") as f:
        json.dump(weaknesses, f, indent=2)

    parent_count = sum(1 for w in weaknesses.values() if w["parent"])
    logger.info(
        "Saved %d entries to %s (%d with parent references)",
        len(weaknesses),
        CWE_FILE,
        parent_count,
    )


if __name__ == "__main__":
    main()
