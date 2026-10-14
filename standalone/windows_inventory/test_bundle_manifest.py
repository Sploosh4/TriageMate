"""Synthetic membership declarations preserve absence, conflicts and exact counts."""

from copy import deepcopy
import sqlite3

import pytest

from .bundle_manifest import (
    member_identity,
    validate_links,
    validate_member,
    validate_summary,
)


def parent(**changes):
    return (
        dict(
            kind="appx",
            native_id="synthetic-bundle",
            name="Synthetic.App",
            publisher="Synthetic publisher",
            version="1.2.3.4",
            family_name="Synthetic.App_publisher",
            is_bundle=True,
            bundle_manifest=dict(
                state="read",
                reason="exact_bundle_manifest_identity",
                sha256="a" * 64,
                member_count=1,
            ),
        )
        | changes
    )


def member(**changes):
    value = (
        dict(
            kind="appx_bundle_member",
            name="Synthetic.App",
            publisher="Synthetic publisher",
            version="5.6.7.8",
            family_name="Synthetic.App_publisher",
            bundle_native_id="synthetic-bundle",
            bundle_version="1.2.3.4",
            manifest_sha256="a" * 64,
            member_index=1,
            member_type="application",
            architecture="x64",
            resource_id="",
            is_stub=False,
        )
        | changes
    )
    value["native_id"] = member_identity(value)
    return value


def test_explicit_member_version_can_differ_from_bundle_version():
    p, m = parent(), member()
    original = deepcopy([p, m])
    validate_links([m, p])
    assert [p, m] == original
    assert m["version"] != p["version"]
    assert not {"installed", "applicability", "user_states"} & m.keys()


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Different.App"},
        {"publisher": "Different publisher"},
        {"family_name": "Different_family"},
        {"bundle_version": "9.9.9.9"},
        {"manifest_sha256": "b" * 64},
        {"bundle_native_id": "another-bundle"},
        {"member_index": 2},
    ],
)
def test_parent_boundary_cannot_be_crossed(change):
    with pytest.raises(ValueError, match="exact collection parent"):
        validate_links([parent(), member(**change)])


def test_no_parent_in_this_collection():
    with pytest.raises(ValueError):
        validate_links([member()])


def test_missing_member_is_not_partial_success():
    with pytest.raises(ValueError, match="Incomplete"):
        validate_links([parent()])


def test_duplicate_and_non_contiguous_members_are_rejected():
    with pytest.raises(sqlite3.IntegrityError):
        validate_links([parent(), member(), member()])
    p = parent()
    p["bundle_manifest"]["member_count"] = 2
    with pytest.raises(ValueError):
        validate_links([p, member(), member(member_index=3)])


@pytest.mark.parametrize(
    "change",
    [
        {"architecture": None},
        {"architecture": "x128"},
        {"is_stub": 1},
        {"member_type": "installed"},
        {"resource_id": "../escape"},
        {"version": "65536.1.2.3"},
        {"version": "1.2"},
        {"member_index": True},
        {"manifest_sha256": "x" * 64},
        {"publisher": ""},
    ],
)
def test_invalid_member_fields(change):
    with pytest.raises(ValueError):
        validate_member(member(**change))


def test_member_identity_is_bound_to_manifest_and_ordinal():
    value = member()
    value["manifest_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="identity differs"):
        validate_member(value)


def test_unavailable_bundle_preserves_zero_without_fabricating_members():
    p = parent(
        bundle_manifest=dict(
            state="unavailable",
            reason="bundle_manifest_read_failed",
            sha256=None,
            member_count=0,
        )
    )
    validate_links([p])
    with pytest.raises(ValueError):
        validate_links([p, member()])
    p["bundle_manifest"]["member_count"] = 1
    with pytest.raises(ValueError):
        validate_summary(p)


def test_bundle_requires_explicit_kind_and_flag():
    for p in (parent(kind="registry"), parent(is_bundle=False), parent(is_bundle=None)):
        with pytest.raises(ValueError):
            validate_summary(p)


def test_legacy_observations_do_not_require_new_members():
    p = parent()
    del p["bundle_manifest"]
    validate_links([p])


def test_cancellation_is_checked_while_streaming():
    seen = []

    def stream():
        for value in [parent(), member()]:
            seen.append(1)
            yield value

    with pytest.raises(ValueError, match="cancelled"):
        validate_links(stream(), cancelled=lambda: len(seen) > 1)
    assert len(seen) == 2


def test_large_stream_uses_complete_counts_without_materializing_members():
    p = parent()
    p["bundle_manifest"]["member_count"] = 10000

    def stream():
        yield p
        for i in range(1, 10001):
            yield member(member_index=i)

    validate_links(stream())


def envelope(missing=False):
    from .test_contract import sample

    p = sample()["records"][1]
    p.update(parent())
    value = sample()
    value["records"] = [p] if missing else [member(), p]
    value["record_count"] = len(value["records"])
    return value


def test_member_contract_and_streaming_stage_preserve_declarations():
    import io
    import json
    from .contract import validate
    from .staging import stage
    from .test_contract import BINDING

    value = envelope()
    raw = json.dumps(value).encode()
    assert validate(raw, BINDING) == value
    with stage(io.BytesIO(raw), BINDING) as staged:
        assert list(staged.records()) == value["records"]
        assert staged.metadata["record_count"] == 2
    assert staged.records_file.closed and staged.source_file.closed


def test_both_materialized_and_streamed_inputs_reject_missing_members():
    import io
    import json
    from .contract import validate
    from .staging import stage
    from .test_contract import BINDING

    raw = json.dumps(envelope(missing=True)).encode()
    with pytest.raises(ValueError, match="Incomplete"):
        validate(raw, BINDING)
    with pytest.raises(ValueError, match="Incomplete"):
        with stage(io.BytesIO(raw), BINDING):
            pytest.fail("An incomplete collection was accepted")


def test_resource_id_is_explicit_and_does_not_require_parsing_native_id():
    import json
    from .contract import validate
    from .test_contract import BINDING, sample

    value = sample()
    value["records"][1]["resource_id"] = "split.scale-200"
    assert validate(json.dumps(value).encode(), BINDING) == value
    value["records"][1]["resource_id"] = "../invalid"
    with pytest.raises(ValueError):
        validate(json.dumps(value).encode(), BINDING)


def test_bundle_resource_marker_requires_explicit_bundle_flag():
    import json
    from .contract import validate
    from .test_contract import BINDING, sample

    value = sample()
    value["records"][1].update(resource_id="~", is_bundle=True)
    assert validate(json.dumps(value).encode(), BINDING) == value
    for flag in (False, None):
        value["records"][1]["is_bundle"] = flag
        with pytest.raises(ValueError):
            validate(json.dumps(value).encode(), BINDING)
