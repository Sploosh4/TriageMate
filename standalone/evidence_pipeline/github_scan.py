"""Compatibility command launcher; implementation lives in collection.github_scan."""

from .collection.github_scan import main


if __name__ == "__main__":
    raise SystemExit(main())
