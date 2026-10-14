"""Compatibility command launcher; implementation lives in collection.cve_repository."""

from .collection.cve_repository import main


if __name__ == "__main__":
    raise SystemExit(main())
