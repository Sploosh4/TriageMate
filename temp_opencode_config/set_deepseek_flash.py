#!/usr/bin/env python3
"""Scan opencode config & agent files in a directory and set all non-builtin
agents to use deepseek/deepseek-v4-flash.

Usage:
    python set_deepseek_flash.py [directory]

If no directory is given, processes the current directory.
The script modifies files in-place.  Backups are created as *.bak.
"""

import json
import os
import re
import sys
import shutil

BUILTIN_AGENTS = frozenset(
    {
        "build",
        "plan",
        "general",
        "explore",
        "scout",
        "compaction",
        "title",
        "summary",
    }
)

MODEL_ID = "deepseek/deepseek-v4-flash"


def is_jsonc(path: str) -> bool:
    return path.endswith(".jsonc")


def strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments (approximate, good enough for opencode configs)."""
    result = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            i += 1
        elif not in_string and ch == "/" and i + 1 < len(text):
            if text[i + 1] == "/":
                i = text.find("\n", i)
                if i == -1:
                    break
                continue  # don't append the newline, just skip it
            elif text[i + 1] == "*":
                end = text.find("*/", i + 2)
                if end == -1:
                    break
                i = end + 2
                continue
            else:
                result.append(ch)
                i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)


def process_config(path: str) -> bool:
    """Update non-builtin agents in a JSON/JSONC config file. Returns True if changed."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    if is_jsonc(path):
        stripped = strip_jsonc_comments(raw)
    else:
        stripped = raw

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as e:
        print(f"  SKIP {path}: invalid JSON ({e})")
        return False

    agents = data.get("agent")
    if not agents or not isinstance(agents, dict):
        print(f"  SKIP {path}: no 'agent' section found")
        return False

    changed = False
    for name, cfg in agents.items():
        if name in BUILTIN_AGENTS:
            print(f"  SKIP  builtin agent '{name}'")
            continue
        if not isinstance(cfg, dict):
            print(f"  SKIP  agent '{name}' config is not an object")
            continue
        current = cfg.get("model")
        if current == MODEL_ID:
            print(f"  OK    agent '{name}' already has {MODEL_ID}")
            continue
        cfg["model"] = MODEL_ID
        changed = True
        print(f"  SET   agent '{name}' -> {MODEL_ID} (was {current})")

    if changed:
        # Re-serialise – preserve original formatting by writing the raw JSONC back
        # with only the model key changed.  We do a targeted string replacement
        # to avoid breaking JSONC comments.
        for name, cfg in agents.items():
            if name in BUILTIN_AGENTS:
                continue
            if not isinstance(cfg, dict):
                continue
            current = cfg.get("model")
            if current != MODEL_ID:
                continue
            # Find the agent block in raw text and patch it
            raw = _set_model_in_raw(raw, name, MODEL_ID)
        with open(path, "w", encoding="utf-8") as f:
            f.write(raw)
        print(f"  WROTE {path}")
        return True
    else:
        print(f"  NOOP  {path}")
        return False


def _set_model_in_raw(raw: str, agent_name: str, model: str) -> str:
    """Replace or add `"model":` inside the first `"agent_name": { ... }` block."""
    # We look for the key-value pair that opens the agent block
    pattern = re.compile(
        r'("' + re.escape(agent_name) + r'"\s*:\s*\{)',
        re.DOTALL,
    )
    match = pattern.search(raw)
    if not match:
        return raw

    start = match.end()
    # Track brace depth to find the end of this agent block
    depth = 1
    end = start
    in_str = False
    while end < len(raw) and depth > 0:
        c = raw[end]
        if c == '"':
            in_str = not in_str
        elif not in_str:
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
        end += 1

    block = raw[start : end - 1]  # content inside { ... }

    # Does a "model" key already exist?
    model_re = re.compile(r'^\s*"model"\s*:', re.MULTILINE)
    replacement = f'"model": "{model}"'
    if model_re.search(block):
        new_block = re.sub(
            r'(^\s*)"model"\s*:\s*"[^"]*"(,)?\s*$',
            lambda m: m.group(1) + replacement + (m.group(2) or ""),
            block,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        new_block = re.sub(
            r'(^\s*)(")',
            lambda m: m.group(1) + replacement + ",\n" + m.group(1) + m.group(2),
            block,
            count=1,
            flags=re.MULTILINE,
        )

    if new_block == block:
        return raw
    return raw[:start] + new_block + raw[end - 1 :]


def process_agent_md(path: str) -> bool:
    """Update frontmatter in a markdown agent file. Returns True if changed."""
    basename = os.path.splitext(os.path.basename(path))[0]
    if basename in BUILTIN_AGENTS:
        print(f"  SKIP  builtin agent '{basename}' (file)")
        return False

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Must have YAML frontmatter between --- markers
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if not fm_match:
        print(f"  SKIP  {path}: no valid frontmatter")
        return False

    fm_text = fm_match.group(1)
    new_fm_text = _set_model_in_frontmatter(fm_text, basename)

    if new_fm_text == fm_text:
        print(f"  OK    agent '{basename}' (file)")
        return False

    new_content = "---\n" + new_fm_text + "\n---\n" + content[fm_match.end() :]
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"  SET   agent '{basename}' (file) -> {MODEL_ID}")
    print(f"  WROTE {path}")
    return True


def _set_model_in_frontmatter(fm: str, agent_name: str) -> str:
    model_line = f"model: {MODEL_ID}"
    if re.search(r"^model:", fm, re.MULTILINE):
        return re.sub(
            r"^model:.*$",
            model_line,
            fm,
            count=1,
            flags=re.MULTILINE,
        )
    else:
        # Insert after description or at the top
        if re.search(r"^description:", fm, re.MULTILINE):
            return re.sub(
                r"^(description:.*)$",
                r"\1\n" + model_line,
                fm,
                count=1,
                flags=re.MULTILINE,
            )
        else:
            return model_line + "\n" + fm


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."

    any_changed = False

    # --- Config files ---
    for fname in os.listdir(root):
        if fname in ("opencode.json", "opencode.jsonc"):
            path = os.path.join(root, fname)
            shutil.copy2(path, path + ".bak")
            print(f"Processing config: {path}")
            if process_config(path):
                any_changed = True

    # --- Agent .md files ---
    for agents_dir in ("agent", "agents"):
        adir = os.path.join(root, agents_dir)
        if not os.path.isdir(adir):
            continue
        for fname in os.listdir(adir):
            if not fname.endswith(".md"):
                continue
            path = os.path.join(adir, fname)
            shutil.copy2(path, path + ".bak")
            print(f"Processing agent: {path}")
            if process_agent_md(path):
                any_changed = True

    if not any_changed:
        print("\nNo changes made.")
    else:
        print("\nDone.  Backups saved as *.bak alongside originals.")


if __name__ == "__main__":
    main()
