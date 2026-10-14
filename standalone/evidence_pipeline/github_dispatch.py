"""Compatibility command launcher; implementation lives in collection.github_dispatch."""

from .collection.github_dispatch import main


if __name__ == "__main__":
    raise SystemExit(main())
