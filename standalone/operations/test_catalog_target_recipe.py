"""Dependent Catalog configuration does not broaden source or network authority."""

from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4
import pytest
from standalone.evidence_pipeline.contracts import SourceScope
from .catalog_target_recipe import CatalogTargetRecipe, REFERENCE
from .dispatch import Job


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "network",
        "origin",
        "tenant",
        "scope",
        "dependency",
        "duplicate",
        "budget",
        "fixture",
    ],
)
def test_explicit_target_recipe_boundaries(tmp_path, damage):
    dependency = str(uuid4())
    scope = SourceScope(
        str(uuid4()),
        "Microsoft Update Catalog",
        "catalog_targets",
        REFERENCE,
        "synthetic",
        "Generated test",
    )
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    recipe = CatalogTargetRecipe(scope, root, (dependency,), tmp_path / "fixture.json")
    now = datetime.now(timezone.utc)
    job = Job(
        str(uuid4()), scope.connection_id, now, now, ((dependency, str(uuid4())),)
    )
    if damage == "network":
        recipe = replace(recipe, allow_network=True)
    elif damage == "origin":
        recipe = replace(recipe, scope=replace(scope, origin="public"))
    elif damage == "tenant":
        recipe = replace(recipe, scope=replace(scope, tenant_id=str(uuid4())))
    elif damage == "scope":
        recipe = replace(
            recipe, scope=replace(scope, scope_reference="https://example.invalid")
        )
    elif damage == "dependency":
        job = replace(job, prerequisite_snapshots=())
    elif damage == "duplicate":
        recipe = replace(recipe, dependencies=(dependency, dependency))
    elif damage == "budget":
        recipe = replace(recipe, target_limit=True)
    elif damage == "fixture":
        recipe = replace(recipe, synthetic_input=None)
    if damage:
        with pytest.raises(ValueError):
            recipe.validate(job)
    else:
        recipe.validate(job)


def test_private_lab_targets_do_not_relabel_catalog_evidence(tmp_path):
    dependency = str(uuid4())
    scope = SourceScope(
        str(uuid4()),
        "Microsoft Update Catalog",
        "catalog_targets",
        REFERENCE,
        "lab",
        "Private designated-lab dependency bindings",
    )
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    recipe = CatalogTargetRecipe(scope, root, (dependency,), allow_network=True)
    now = datetime.now(timezone.utc)
    job = Job(
        str(uuid4()), scope.connection_id, now, now, ((dependency, str(uuid4())),)
    )
    recipe.validate(job)
    for changes in (
        {"input_kind": "updates"},
        {"input_kind": "catalog_search"},
        {"source": "NVD"},
        {"scope_reference": "other"},
        {"tenant_id": str(uuid4())},
    ):
        with pytest.raises(ValueError):
            replace(scope, **changes)
    with pytest.raises(ValueError):
        replace(recipe, allow_network=False).validate(job)
    with pytest.raises(ValueError):
        replace(recipe, synthetic_input=tmp_path / "fixture.json").validate(job)
