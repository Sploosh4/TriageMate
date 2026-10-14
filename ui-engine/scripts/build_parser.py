"""Explicit Linux parser preparation; no runtime installs or database changes."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

REVISION = "fce106abf41205e5d0db47bea7de44ad1e36f7a5"  # upstream tag 16-5.2.0
SHA256 = "40e39025f9d587747f760af2b6879d8896c0095eed4d2a3b2a8af8adab58352a"
URL = f"https://codeload.github.com/pganalyze/libpg_query/tar.gz/{REVISION}"
DESTINATION = Path(__file__).resolve().parents[1] / "work/parser"


def source_archive(path):
    if not path.is_file():
        raise ValueError(
            "Parser source archive is missing; provide --source-archive or explicitly use --allow-downloads"
        )
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SHA256:
        raise ValueError("Parser source checksum mismatch; nothing installed")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--destination", type=Path, default=DESTINATION)
    parser.add_argument("--allow-downloads", action="store_true")
    args = parser.parse_args(argv)
    cached = args.source_archive or args.destination / "source.tar.gz"
    # A bad cache must fail, never silently fall back to the network.
    if cached.exists() or not args.allow_downloads:
        source_archive(cached)
    with tempfile.TemporaryDirectory(prefix="triagemate-parser-") as scratch:
        root = Path(scratch)
        archive = cached
        if not cached.exists():
            archive = root / "source.tar.gz"
            with urlopen(URL, timeout=30) as response, archive.open("xb") as stream:
                count = 0
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > 50_000_000:
                        raise ValueError("Parser source download exceeds its bound")
                    stream.write(chunk)
            source_archive(archive)
        with tarfile.open(archive) as bundle:
            bundle.extractall(root, filter="data")
        source = root / f"libpg_query-{REVISION}"
        subprocess.run(["make", "-j4", "build_shared", "test"], cwd=source, check=True)
        args.destination.mkdir(parents=True, exist_ok=True)
        cache_target = args.destination / "source.tar.gz"
        if archive.resolve() != cache_target.resolve():
            shutil.copyfile(archive, cache_target.with_suffix(".gz.new"))
            cache_target.with_suffix(".gz.new").replace(cache_target)
        # Replace atomically so a running server keeps its existing mapped library.
        target = args.destination / "libpg_query.so"
        shutil.copyfile(source / "libpg_query.so", target.with_suffix(".so.new"))
        target.with_suffix(".so.new").replace(target)
        print(f"Installed libpg_query 16-5.2.0 at {target}; restart the UI service.")


if __name__ == "__main__":
    main()
