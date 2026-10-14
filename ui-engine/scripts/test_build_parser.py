"""Synthetic archive checks; no network, compiler or installed parser mutation."""

import hashlib
import io
import tarfile

import pytest

import build_parser as builder


@pytest.fixture
def archive(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-source.tar.gz"
    data = b"synthetic parser artifact"
    with tarfile.open(path, "w:gz") as bundle:
        item = tarfile.TarInfo(f"libpg_query-{builder.REVISION}/libpg_query.so")
        item.size = len(data)
        bundle.addfile(item, io.BytesIO(data))
    monkeypatch.setattr(
        builder, "SHA256", hashlib.sha256(path.read_bytes()).hexdigest()
    )
    monkeypatch.setattr(builder.subprocess, "run", lambda *args, **kwargs: None)
    return path, tmp_path / "destination", data


def test_missing_cache_never_downloads_without_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(
        builder,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("Downloaded without permission"),
    )
    with pytest.raises(ValueError, match="missing"):
        builder.main(["--destination", str(tmp_path / "absent")])
    assert not (tmp_path / "absent").exists()


def test_verified_archive_is_reused_even_when_downloads_allowed(archive, monkeypatch):
    path, destination, data = archive
    monkeypatch.setattr(
        builder,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("Downloaded despite verified cache"),
    )
    builder.main(["--source-archive", str(path), "--destination", str(destination)])
    assert (destination / "libpg_query.so").read_bytes() == data
    assert (destination / "source.tar.gz").read_bytes() == path.read_bytes()
    builder.main(["--destination", str(destination), "--allow-downloads"])


def test_bad_archive_never_falls_back_or_replaces_library(archive, monkeypatch):
    path, destination, _ = archive
    destination.mkdir()
    library = destination / "libpg_query.so"
    library.write_bytes(b"existing")
    path.write_bytes(b"wrong archive")
    monkeypatch.setattr(
        builder,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("Downloaded after checksum failure"),
    )
    with pytest.raises(ValueError, match="checksum"):
        builder.main(
            [
                "--source-archive",
                str(path),
                "--destination",
                str(destination),
                "--allow-downloads",
            ]
        )
    assert library.read_bytes() == b"existing"


def test_explicit_download_is_verified_and_cached(archive, monkeypatch):
    path, destination, data = archive
    calls = []

    def download(url, timeout):
        calls.append(url)
        return io.BytesIO(path.read_bytes())

    monkeypatch.setattr(builder, "urlopen", download)
    builder.main(["--destination", str(destination), "--allow-downloads"])
    assert calls == [builder.URL]
    assert (destination / "libpg_query.so").read_bytes() == data


def test_failed_build_preserves_installed_library(archive, monkeypatch):
    path, destination, _ = archive
    destination.mkdir()
    library = destination / "libpg_query.so"
    library.write_bytes(b"existing")

    def fail_build(*args, **kwargs):
        raise builder.subprocess.CalledProcessError(1, "make")

    monkeypatch.setattr(builder.subprocess, "run", fail_build)
    with pytest.raises(builder.subprocess.CalledProcessError):
        builder.main(["--source-archive", str(path), "--destination", str(destination)])
    assert library.read_bytes() == b"existing"
    assert not (destination / "source.tar.gz").exists()
