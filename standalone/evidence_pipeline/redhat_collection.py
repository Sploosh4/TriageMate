"""Compatibility command launcher; implementation lives in collection.redhat_collection."""

from .collection.redhat_collection import main


if __name__ == "__main__":
    raise SystemExit(main())
