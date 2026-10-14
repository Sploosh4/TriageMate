"""Shared validation primitives enforce current evidence boundaries."""

import pytest
from pydantic import TypeAdapter, ValidationError

from evidence_types import NonEmptyText, Sha256, StrictModel


def test_nonempty_text_trims_and_rejects_empty_values():
    adapter = TypeAdapter(NonEmptyText)
    assert (
        adapter.validate_python("  synthetic observation  ") == "synthetic observation"
    )
    for value in ("", "   ", None):
        with pytest.raises(ValidationError):
            adapter.validate_python(value)


def test_sha256_requires_exact_lowercase_digest():
    adapter = TypeAdapter(Sha256)
    assert adapter.validate_python("a" * 64) == "a" * 64
    for value in ("A" * 64, "a" * 63, "a" * 65, "g" * 64):
        with pytest.raises(ValidationError):
            adapter.validate_python(value)


def test_evidence_models_reject_extra_fields_and_mutation():
    class Observation(StrictModel):
        label: NonEmptyText

    observation = Observation(label="synthetic")
    with pytest.raises(ValidationError):
        Observation(label="synthetic", extra="unexpected")
    with pytest.raises(ValidationError):
        observation.label = "changed"
