"""Read-only launcher interface to the same path resolver used by the API."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .service_paths import startup_service_paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    args = parser.parse_args()
    try:
        selected = startup_service_paths(args.checkout)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Application storage is unavailable: {exc}\n")
    print(json.dumps(asdict(selected), default=str, sort_keys=True))


if __name__ == "__main__":
    main()
