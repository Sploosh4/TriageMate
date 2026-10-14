"""Explicit offline import of a selected capture into its registered lab/synthetic scope."""

import argparse
from contextlib import closing
import json

import psycopg2

from standalone.evidence_pipeline.runtime import connect
from .component_check_commands import selected_file_inputs
from .selected_component_store import persist


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-snapshot", required=True)
    for name in ("selected", "binding", "evidence", "sources"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        values = vars(args).copy()
        inventory_attempt_id = values.pop("inventory_snapshot")
        inputs = selected_file_inputs(**values)
        with closing(connect()) as connection, connection:
            result = persist(connection, inventory_attempt_id, **inputs)
        # Only acknowledge after commit; no raw identities/evidence in errors.
        print(json.dumps(result, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError, RecursionError, psycopg2.Error):
        parser.exit(
            2,
            "Selected component import failed; verify the registered snapshot and retained evidence.\n",
        )


if __name__ == "__main__":
    main()
