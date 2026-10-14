"""Check tracked text for high-confidence secrets; permit two exact negative fixtures."""

from pathlib import Path
import re
import subprocess

PATTERN = re.compile(
    r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|"
    r"-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"
)
FIXTURE = "backend/tests/test_microsoft_provider_contract_negatives.py"
ALLOWED = {
    '"gh' + 'p_abcdefghijklmnopqrstuvwxyz0123456789AB",',
    '"-----BEGIN OPENSSH ' + 'PRIVATE KEY-----",',
}


def main():
    failed = False
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).decode().split("\0")
    for name in filter(None, paths):
        path = Path(name)
        if not path.is_file():
            continue
        try:
            lines = path.read_text().splitlines()
        except UnicodeError:
            continue
        for number, line in enumerate(lines, 1):
            if PATTERN.search(line) and not (
                name == FIXTURE and line.strip() in ALLOWED
            ):
                print(f"{name}:{number}: potential secret pattern (value withheld)")
                failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
