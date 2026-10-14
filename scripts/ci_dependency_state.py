"""Detect installed dependency changes without downloading or executing packages."""

import hashlib
import json
from pathlib import Path
import sys


def inventory(root, *, include_ui=True, include_artifacts=True):
    result = {}
    bases = (
        ("venv", "node_modules", "ui-engine/node_modules")
        if include_ui
        else ("venv", "node_modules")
    )
    if include_artifacts:
        bases += ("parser", "browser")
    for base in bases:
        directory = root / base
        if not directory.is_dir():
            raise ValueError(f"Missing dependency directory: {base}")
        for path in sorted(directory.rglob("*")):
            if any(
                part in {"__pycache__", ".cache", ".vite", ".vite-temp"}
                for part in path.relative_to(directory).parts
            ):
                continue
            name = str(path.relative_to(root))
            if path.is_symlink():
                result[name] = "link:" + str(path.readlink())
            elif path.is_file():
                with path.open("rb") as stream:
                    result[name] = (
                        f"{path.stat().st_mode & 0o777:o}:"
                        + hashlib.file_digest(stream, "sha256").hexdigest()
                    )
    return result


def main():
    action, folder = sys.argv[1:]
    root = Path(folder)
    stamp = root / "installed-files.json"
    if action == "record":
        stamp.write_text(
            json.dumps({"version": 3, "files": inventory(root)}, sort_keys=True)
        )
    elif action in {"verify", "verify-current"}:
        stored = json.loads(stamp.read_text())
        if action == "verify-current" and stored.get("version") != 3:
            raise ValueError("Dependency inventory requires manual UI artifact upgrade")
        # Verify the exact old inventory before upgrading an existing installation.
        # New records always include the standalone UI dependencies.
        if stored.get("version") in {2, 3}:
            previous = stored["files"]
            current = inventory(root, include_artifacts=stored["version"] == 3)
        elif "version" not in stored:
            previous = stored
            current = inventory(root, include_ui=False, include_artifacts=False)
        else:
            raise ValueError("Unknown dependency inventory version")
        changed = sorted(
            key
            for key in current.keys() | previous.keys()
            if current.get(key) != previous.get(key)
        )
        if changed:
            print(
                "Installed dependency files changed: " + ", ".join(changed[:10]),
                file=sys.stderr,
            )
            return 1
    else:
        raise ValueError("Expected record, verify or verify-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
