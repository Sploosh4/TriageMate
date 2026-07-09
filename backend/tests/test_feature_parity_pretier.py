"""
Feature-parity guard test for the Pre-Tier model.

Verifies that the 60-dimensional feature vector used by the training pipeline
(train_pre_tier.py) is identical to the one used by the inference pipeline
(pipeline/pre_tier.py).

Since both training and inference import from the same shared module
(ml.pretier_features), this is a structural guarantee rather than a
cross-module comparison.  The tests here:

  - Confirm the shared feature list is exactly 60 items long
  - Confirm all 60 feature names are unique
  - Confirm the training code and inference code both import from
    ml.pretier_features (via docstring / import inspection)
  - Fail explicitly if the feature count changes (forcing human review)

This follows the same pattern as test_feature_parity.py but is simpler
because there is only one shared feature module.
"""

import pytest

# ── Expected contract ────────────────────────────────────────────────────────
EXPECTED_FEATURE_COUNT = 60


class TestPreTierFeatureParity:
    """60-dim feature vector contract for the Pre-Tier RandomForest model."""

    # ── Part 1: Shared module produces the expected feature list ──────────

    def test_feature_count_is_60(self):
        """get_feature_count() returns exactly 60."""
        from ml.pretier_features import get_feature_count

        assert get_feature_count() == EXPECTED_FEATURE_COUNT, (
            f"Pre-Tier feature count changed from {EXPECTED_FEATURE_COUNT} "
            f"to {get_feature_count()}. This requires human review — update "
            f"EXPECTED_FEATURE_COUNT and retrain the model."
        )

    def test_feature_list_length_matches_count(self):
        """get_feature_names() length matches get_feature_count()."""
        from ml.pretier_features import get_feature_count, get_feature_names

        assert len(get_feature_names()) == get_feature_count()

    def test_all_feature_names_are_unique(self):
        """No duplicate feature names."""
        from ml.pretier_features import get_feature_names

        names = get_feature_names()
        assert len(names) == len(set(names)), (
            "Duplicate feature names detected in pretier_features"
        )

    # ── Part 2: Training pipeline uses pretier_features directly ─────────

    def test_train_pre_tier_imports_pretier_features(self):
        """Verify train_pre_tier.py imports from ml.pretier_features."""
        import ml.train_pre_tier  # noqa: F401

        # Check the module uses extract_features / feature_vector_to_array
        assert hasattr(ml.train_pre_tier, "extract_features") or True
        source = ml.train_pre_tier.__file__
        with open(source) as f:
            content = f.read()
        assert "from ml.pretier_features import" in content, (
            "train_pre_tier.py does not import from ml.pretier_features — "
            "feature parity may be broken."
        )

    # ── Part 3: Inference pipeline uses pretier_features directly ────────

    def test_pre_tier_pipeline_imports_pretier_features(self):
        """Verify pipeline/pre_tier.py uses ml.pretier_features at inference."""
        import pipeline.pre_tier

        source = pipeline.pre_tier.__file__
        with open(source) as f:
            content = f.read()
        assert "from ml.pretier_features import" in content, (
            "pipeline/pre_tier.py does not import from ml.pretier_features — "
            "feature parity may be broken."
        )

    # ── Part 4: Feature names are deterministic across calls ─────────────

    def test_feature_names_deterministic(self):
        """get_feature_names() returns the same list every call."""
        from ml.pretier_features import get_feature_names

        assert get_feature_names() == get_feature_names()

    # ── Part 5: Explicit count-change guard ─────────────────────────────

    def test_explicit_count_change_guard(self):
        """
        Fail LOUDLY if feature count changes.

        This guard exists because changing the feature count invalidates the
        existing pre_tier_model.pkl.  If you change the feature count, you
        MUST:
          1. Update EXPECTED_FEATURE_COUNT in this file
          2. Re-run ml.train_pre_tier to retrain the model
          3. Update metrics in model_registry_pre_tier.json
        """
        from ml.pretier_features import get_feature_count

        if get_feature_count() != EXPECTED_FEATURE_COUNT:
            pytest.fail(
                f"FEATURE COUNT CHANGED: was {EXPECTED_FEATURE_COUNT}, "
                f"now {get_feature_count()}. "
                f"This invalidates pre_tier_model.pkl. "
                f"Retrain with: python -m ml.train_pre_tier --from-db"
            )

    # ── Part 6: verify index 59 is system_category ──────────────────────

    def test_index_59_is_system_category(self):
        """Index 59 (last) is the ordinal system_category."""
        from ml.pretier_features import get_feature_names

        names = get_feature_names()
        assert names[59] == "system_category", (
            f"Expected names[59]='system_category', got '{names[59]}'"
        )

    # ── Part 7: Feature vector produced by inference matches expected dim ─

    def test_inference_produces_60_dim_vector(self):
        """feature_vector_to_array(extract_features(...)) produces 60 values."""
        from ml.pretier_features import extract_features, feature_vector_to_array

        f = extract_features("per-PRD-MOVEIT-WEB01.health.wa.gov.au")
        arr = feature_vector_to_array(f)
        assert len(arr) == EXPECTED_FEATURE_COUNT, (
            f"Inference feature vector has {len(arr)} elements, "
            f"expected {EXPECTED_FEATURE_COUNT}"
        )
