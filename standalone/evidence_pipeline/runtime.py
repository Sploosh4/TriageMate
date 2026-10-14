"""Explicit current-schema setup and restricted connections; no collection."""

import argparse
from contextlib import closing

from backend.database.connections import connect_pipeline, local_database
from backend.database.installation import setup as install_existing, upgrade_existing
from backend.database.schema import verify_supported


def credential_file():
    return local_database().CREDENTIALS / "pipeline-writer.json"


def setup(*, profile="empty"):
    """Install the complete baseline on an explicitly provisioned local target."""
    return install_existing(local_database(), profile=profile)


def connect():
    return connect_pipeline()


def check():
    with closing(local_database().connect()) as conn, conn.cursor() as cur:
        verify_supported(cur)
    with closing(connect()) as conn, conn.cursor() as cur:
        cur.execute("SELECT current_user")
        if cur.fetchone() != ("tm_pipeline_writer",):
            raise ValueError("Unexpected writer identity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "check", "upgrade"))
    parser.add_argument(
        "--profile", choices=("empty", "synthetic", "runner"), default="empty"
    )
    args = parser.parse_args()
    try:
        if args.command == "setup":
            changed = setup(profile=args.profile)
            print(
                "Evidence baseline installed."
                if changed
                else "Evidence baseline verified; unchanged."
            )
        elif args.command == "upgrade":
            changed = upgrade_existing(local_database())
            print(
                "Registered database revisions applied."
                if changed
                else "Database is current; unchanged."
            )
        else:
            check()
            print("Evidence schema and restricted pipeline login verified.")
    except Exception:
        raise SystemExit(
            "Database setup/check failed; inspect local configuration and explicit baseline adoption requirements."
        ) from None


if __name__ == "__main__":
    main()
