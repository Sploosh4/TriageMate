"""Synthetic declaration-reader tests, not Microsoft applicability evidence."""

import hashlib

import pytest

from .servicing_manifest import read_manifest


IDENTITY = '<assemblyIdentity name="Synthetic" version="10.0.26100.1" processorArchitecture="amd64" publicKeyToken="synthetic" language="neutral"/>'


def document(body=IDENTITY):
    return (
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">'
        + body
        + "</assembly>"
    ).encode()


def read(raw):
    return read_manifest(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_exact_root_identity_literal_file_paths_and_dependencies():
    raw = document(
        IDENTITY
        + '<file name="same.dll" destinationPath="$(runtime.windows)\\First\\"/><file name="same.dll" destinationPath="$(runtime.windows)\\Second\\"/><parent>'
        + IDENTITY
        + '</parent><dependency optional="true"><dependentAssembly dependencyType="install">'
        + IDENTITY
        + "</dependentAssembly></dependency>"
    )
    result = read(raw)
    assert result["assembly"]["version"] == "10.0.26100.1"
    assert len(result["declared_files"]) == 2
    assert (
        result["declared_files"][0]["destinationPath"]
        != result["declared_files"][1]["destinationPath"]
    )
    assert len(result["declared_dependencies"]) == 1
    assert result["declared_dependencies"][0]["dependency"] == {"optional": "true"}
    assert result["scope"] == "decoded_servicing_declarations_only"


@pytest.mark.parametrize(
    "raw",
    [
        document(""),
        document(IDENTITY + IDENTITY),
        document(IDENTITY.replace(' version="10.0.26100.1"', "")),
        document(IDENTITY.replace("10.0.26100.1", "*")),
        document(IDENTITY + "<file/>"),
        document(IDENTITY + "<dependency><dependentAssembly/></dependency>"),
        b"<assembly/>",
        b"<assembly",
        b'<!DOCTYPE assembly [<!ENTITY data SYSTEM "file:///etc/passwd">]>'
        + document(),
        document().replace(b"asm.v3", b"other"),
    ],
)
def test_ambiguous_incomplete_and_unsafe_xml_rejected(raw):
    with pytest.raises(ValueError):
        read(raw)


def test_bytes_cannot_be_replaced_under_an_existing_proof_hash():
    with pytest.raises(ValueError, match="hash mismatch"):
        read_manifest(document(), expected_sha256="0" * 64)
