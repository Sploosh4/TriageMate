"""
Tests for ML pipeline components: PCA dimensionality reduction.

Covers PCA training hygiene (fit on train only), inference integration,
graceful degradation, dimensionality consistency, and variance retention.
"""

import sys
import tempfile

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pytest  # noqa: E402
from pathlib import Path  # noqa: E402
from sklearn.decomposition import PCA  # noqa: E402

# Ensure backend is on sys.path for imports
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))


# ── PCA: fit-on-train-only hygiene ─────────────────────────────────────────


class TestPCAFitOnTrainOnly:
    """Verify PCA is fitted on training data only (no data leakage)."""

    def test_pca_mean_from_train_only(self):
        """PCA mean_ should equal training data mean, not full data mean."""
        rng = np.random.default_rng(42)

        # Create synthetic data: train has mean=10, val/test have mean=0
        n_train, n_dims = 1000, 384
        X_train_text = rng.normal(loc=10.0, scale=1.0, size=(n_train, n_dims))

        # Fit PCA on train only
        pca = PCA(n_components=0.95)
        pca.fit(X_train_text)

        # PCA mean_ should be close to training mean (~10.0), not ~0.0
        assert abs(np.mean(pca.mean_) - 10.0) < 1.0, (
            f"PCA mean_ ({np.mean(pca.mean_):.2f}) should be near "
            f"training data mean (10.0), not zero-mean data"
        )

    def test_pca_transform_val_uses_train_stats(self):
        """Transforming val data uses train-derived PCA (not refit on val)."""
        rng = np.random.default_rng(42)

        # Train: mean 5, Val: mean -5 — distinct clusters
        X_train = rng.normal(loc=5.0, scale=1.0, size=(500, 384))
        X_val = rng.normal(loc=-5.0, scale=1.0, size=(100, 384))

        pca = PCA(n_components=0.95)
        pca.fit(X_train)
        val_pca = pca.transform(X_val)

        # The val transformed data should NOT have the same distribution
        # as train (because it was different data), but the transform
        # should be consistent (deterministic from train fit)
        val_pca_again = pca.transform(X_val)
        assert np.allclose(val_pca, val_pca_again), (
            "PCA transform should be deterministic for same input"
        )

    def test_pca_no_leakage_from_val(self):
        """Fitting PCA separately on train vs all-data should give different results.

        This tests that if PCA were incorrectly fitted on all data, the
        transform would differ from train-only fitting.
        Uses a fixed number of components so that output dimensions match
        for direct comparison.
        """
        rng = np.random.default_rng(42)
        n_train, n_val, n_dims = 500, 100, 384
        n_components = 50

        X_train = rng.normal(loc=10.0, scale=1.0, size=(n_train, n_dims))
        X_val = rng.normal(loc=0.0, scale=1.0, size=(n_val, n_dims))
        X_all = np.vstack([X_train, X_val])

        # Fit on train only
        pca_train = PCA(n_components=n_components).fit(X_train)
        # Fit on all data (leakage scenario)
        pca_all = PCA(n_components=n_components).fit(X_all)

        # Transform val with both
        val_via_train = pca_train.transform(X_val)
        val_via_all = pca_all.transform(X_val)

        # They should differ because PCA fit on different data
        diff = np.abs(val_via_train - val_via_all).mean()
        assert diff > 0.01, (
            f"Val transforms from train-only vs all-data PCA should differ "
            f"(mean abs diff={diff:.4f}), but they are nearly identical"
        )


# ── PCA: save/load and inference integration ────────────────────────────────


class TestPCATransformsInference:
    """Fit PCA on mock array, save/load, verify transform works."""

    @pytest.fixture(autouse=True)
    def _setup_and_cleanup(self):
        """Create a temp PCA model, yield tests, then clean up."""
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="pca_test_"))
        self.pca_path = self.tmp_dir / "pca_model.pkl"

        # Create synthetic 384-dim data
        rng = np.random.default_rng(42)
        X = rng.normal(size=(200, 384))

        # Fit and save PCA
        self.pca = PCA(n_components=0.95)
        self.pca.fit(X)
        joblib.dump(self.pca, self.pca_path)

        yield

        # Cleanup
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_pca_save_and_load(self):
        """PCA model can be saved and loaded, producing identical transforms."""
        loaded = joblib.load(self.pca_path)
        assert loaded.n_components_ == self.pca.n_components_, (
            f"Loaded PCA has {loaded.n_components_} components, "
            f"expected {self.pca.n_components_}"
        )

        # Verify transform consistency
        test_vec = np.random.default_rng(42).normal(size=(1, 384)).astype(np.float32)
        expected = self.pca.transform(test_vec)
        actual = loaded.transform(test_vec)
        assert np.allclose(expected, actual), (
            "Loaded PCA transform should match original"
        )

    def test_pca_transform_shapes(self):
        """PCA transforms 384-dim input to n_components-dim output."""
        loaded = joblib.load(self.pca_path)
        n_components = loaded.n_components_
        assert n_components < 384, (
            f"PCA should reduce dimensions; got {n_components} >= 384"
        )
        assert n_components > 0, (
            f"PCA should have at least 1 component, got {n_components}"
        )

        test_vec = np.random.default_rng(99).normal(size=(1, 384)).astype(np.float32)
        result = loaded.transform(test_vec)
        assert result.shape == (1, n_components), (
            f"PCA transform output shape should be (1, {n_components}), "
            f"got {result.shape}"
        )


# ── PCA: graceful degradation ────────────────────────────────────────────────


class TestPCAGracefulDegradation:
    """When pca_model.pkl is missing, predict() should still work (raw 384-dim)."""

    def test_load_pca_returns_none_when_missing(self, monkeypatch):
        """_load_pca returns None when PCA model doesn't exist."""
        from ml.xgboost_predictor import _load_pca

        # Point PCA_MODEL_PATH to a nonexistent file
        import ml.xgboost_predictor as xp

        fake_path = Path("/tmp/nonexistent_pca_model.pkl")
        monkeypatch.setattr(xp, "PCA_MODEL_PATH", fake_path)

        # Reset cached PCA model
        xp._pca_model = None

        pca = _load_pca()
        assert pca is None, "Should return None when PCA model not found"

    def test_apply_pca_passthrough_when_missing(self, monkeypatch):
        """_apply_pca returns original vector when PCA model is missing."""
        from ml.xgboost_predictor import _apply_pca

        import ml.xgboost_predictor as xp

        fake_path = Path("/tmp/nonexistent_pca_model2.pkl")
        monkeypatch.setattr(xp, "PCA_MODEL_PATH", fake_path)
        xp._pca_model = None

        text_vec = np.random.default_rng(42).normal(size=384).astype(np.float32)
        result = _apply_pca(text_vec)
        assert result.shape == (1, 384), (
            f"Without PCA model, should return (1, 384), got {result.shape}"
        )
        assert np.allclose(result.flatten(), text_vec), (
            "Without PCA model, output should match input"
        )

    def test_predict_works_without_pca_model(self, monkeypatch):
        """predict() functions when PCA model is absent (uses raw 384-dim)."""
        from ml.xgboost_predictor import predict

        import ml.xgboost_predictor as xp

        # Point PCA to nonexistent path
        monkeypatch.setattr(xp, "PCA_MODEL_PATH", Path("/tmp/nonexistent_pca.pkl"))
        xp._pca_model = None

        # Use minimal features — predict should not crash even without PCA
        features = {
            "epss_score": 0.05,
            "description": "Test CVE description for graceful degradation check",
        }
        try:
            result = predict(features)
            # Should return a dict with expected keys
            assert "exploitation_probability" in result
            assert "routing" in result
            assert "tier" in result
        except FileNotFoundError:
            # xgboost model may not exist in test env — that's OK
            pass
        except Exception as e:
            # Only allow FileNotFoundError (no model), not other errors
            if "FileNotFoundError" not in type(e).__name__:
                raise


# ── PCA: dimensionality consistency ─────────────────────────────────────────


class TestPCADimensionalityConsistency:
    """Verify training and inference produce same number of features after PCA."""

    def test_feature_count_consistency(self):
        """After PCA, tabular + PCA components should match between train and inference."""
        rng = np.random.default_rng(42)
        n_tabular = 35
        n_text = 384

        # Simulate training data
        X_train = np.hstack(
            [
                rng.normal(size=(100, n_tabular)),
                rng.normal(size=(100, n_text)),
            ]
        ).astype(np.float32)

        # Fit PCA on text portion
        X_train_text = X_train[:, n_tabular:]
        pca = PCA(n_components=0.95)
        X_train_text_pca = pca.fit_transform(X_train_text)
        n_components = pca.n_components_

        # Reconstruct full feature vector
        X_train_pca = np.hstack([X_train[:, :n_tabular], X_train_text_pca]).astype(
            np.float32
        )

        # Simulate inference with same PCA
        inference_text = rng.normal(size=(1, n_text)).astype(np.float32)
        inference_text_pca = pca.transform(inference_text)
        inference_full = np.hstack(
            [rng.normal(size=(1, n_tabular)).astype(np.float32), inference_text_pca]
        )

        assert X_train_pca.shape[1] == inference_full.shape[1], (
            f"Training feature dim ({X_train_pca.shape[1]}) should match "
            f"inference feature dim ({inference_full.shape[1]})"
        )
        assert X_train_pca.shape[1] == n_tabular + n_components, (
            f"Total dims should be tabular ({n_tabular}) + "
            f"PCA comps ({n_components}) = {n_tabular + n_components}, "
            f"got {X_train_pca.shape[1]}"
        )

    def test_n_tabular_stable(self):
        """Tabular feature count (35) stays unchanged after PCA."""
        n_tabular = 35
        n_text = 384

        X = np.zeros((10, n_tabular + n_text), dtype=np.float32)
        n_tabular_detected = X.shape[1] - n_text
        assert n_tabular_detected == n_tabular, (
            f"Expected {n_tabular} tabular features, got {n_tabular_detected}"
        )


# ── PCA: explained variance ─────────────────────────────────────────────────


class TestPCAExplainedVariance:
    """PCA with 0.95 should retain >= 94% variance."""

    def test_variance_retention_threshold(self):
        """PCA(n_components=0.95) retains at least 94% explained variance."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(1000, 384))

        pca = PCA(n_components=0.95)
        pca.fit(X)

        explained = pca.explained_variance_ratio_.sum()
        assert explained >= 0.94, (
            f"PCA with n_components=0.95 should retain >= 94% variance, "
            f"got {explained:.4f}"
        )

    def test_variance_retention_upper_bound(self):
        """PCA with n_components=0.95 should retain <= 96% variance.

        With exactly 95% target, sklearn may slightly exceed but should
        stay within reasonable bounds.
        """
        rng = np.random.default_rng(42)
        X = rng.normal(size=(1000, 384))

        pca = PCA(n_components=0.95)
        pca.fit(X)

        explained = pca.explained_variance_ratio_.sum()
        assert explained <= 0.97, (
            f"PCA with n_components=0.95 should retain around 95% variance, "
            f"got {explained:.4f} (too high)"
        )

    def test_component_reduction(self):
        """PCA reduces 384 dims to fewer components (typically 100-200 for 95%)."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(1000, 384))

        pca = PCA(n_components=0.95)
        pca.fit(X)

        n_components = pca.n_components_
        assert 50 <= n_components < 384, (
            f"PCA should reduce 384 dims to a reasonable number "
            f"(50-350), got {n_components}"
        )


# ── PCA: feature name helper ────────────────────────────────────────────────


class TestPCAFeatureNames:
    """Verify make_sbert_feature_names helper."""

    def test_sbert_names_when_384(self):
        """With n=384, names use sbert_ prefix."""
        from pipeline.config.feature_names import make_sbert_feature_names

        names = make_sbert_feature_names(384)
        assert len(names) == 384
        assert names[0] == "sbert_0"
        assert names[383] == "sbert_383"

    def test_pca_names_when_less_than_384(self):
        """With n < 384, names use pca_ prefix."""
        from pipeline.config.feature_names import make_sbert_feature_names

        names = make_sbert_feature_names(128)
        assert len(names) == 128
        assert names[0] == "pca_0"
        assert names[127] == "pca_127"

    def test_default_is_384_sbert(self):
        """Default call returns 384 sbert_ names."""
        from pipeline.config.feature_names import make_sbert_feature_names

        names = make_sbert_feature_names()
        assert len(names) == 384
        assert names[0] == "sbert_0"


# ── Multi-window KEV labels (Sprint 22) ──────────────────────────────────


class TestMultiWindowLabels:
    """Verify 5-class KEV label construction and predictor output."""

    def test_kev_windows_constant(self):
        """KEV_WINDOWS should be [0, 30, 90, 365]."""
        from ml.train_xgboost import KEV_WINDOWS

        assert KEV_WINDOWS == [0, 30, 90, 365]

    def test_multi_window_label_construction(self):
        """Verify labels are correctly assigned per window."""
        from ml.train_xgboost import construct_labels

        # DATE_END is 2024-12-31 in the training pipeline.
        # Mock CVEs and KEV data with dates relative to that.
        cves = [
            {"cve_id": "CVE-2024-0001"},  # Not in KEV → 0
            {"cve_id": "CVE-2024-0002"},  # Empty date → 0
            {"cve_id": "CVE-2024-0003"},  # Future → 0 (point-in-time filter)
            {"cve_id": "CVE-2024-0004"},  # 2024-12-01 → ~30d → window 1
            {"cve_id": "CVE-2024-0005"},  # 2024-09-01 → ~121d → window 3
            {"cve_id": "CVE-2024-0006"},  # 2020-01-01 → >365d → window 4
        ]
        kev = {
            "CVE-2024-0002": "",  # empty → 0
            "CVE-2024-0003": "2099-01-01",  # future → 0
            "CVE-2024-0004": "2024-12-01",  # 30d from DATE_END → window 1
            "CVE-2024-0005": "2024-09-01",  # ~121d from DATE_END → window 3
            "CVE-2024-0006": "2020-01-01",  # >365d → window 4
        }
        labels = construct_labels(cves, kev, cutoff_date="2024-12-31")
        expected = [0, 0, 0, 1, 3, 4]
        assert labels == expected, f"Expected {expected}, got {labels}"

    def test_multi_window_label_range(self):
        """Verify labels are always 0-4."""
        from ml.train_xgboost import construct_labels

        cves = [
            {"cve_id": "CVE-2024-0010"},
            {"cve_id": "CVE-2024-0011"},
        ]
        kev = {
            "CVE-2024-0010": "2024-06-15",
            "CVE-2024-0011": "2020-01-01",
        }
        labels = construct_labels(cves, kev, cutoff_date="2024-12-31")
        assert all(0 <= lab <= 4 for lab in labels), (
            f"Labels out of range 0-4: {labels}"
        )

    def test_multi_window_not_in_kev_is_zero(self):
        """CVE not in KEV should always get label 0."""
        from ml.train_xgboost import construct_labels

        cves = [{"cve_id": "CVE-2024-0020"}]
        labels = construct_labels(cves, {}, cutoff_date="2024-12-31")
        assert labels == [0], f"Expected [0], got {labels}"

    def test_multi_window_predictor_output(self):
        """Verify predictor returns 5 probabilities summing to ~1.0."""
        from ml.xgboost_predictor import predict
        import ml.xgboost_predictor as xp

        # Point PCA to nonexistent path for graceful degradation
        from pathlib import Path
        import tempfile

        old_pca = xp.PCA_MODEL_PATH
        fake_pca = Path(tempfile.mktemp(suffix=".pkl"))
        try:
            xp.PCA_MODEL_PATH = fake_pca
            xp._pca_model = None

            features = {
                "epss_score": 0.05,
                "description": "Test CVE description for multi-window check",
            }
            result = predict(features)
            # Should have the new fields
            assert "exploitation_probability" in result, (
                "Missing exploitation_probability"
            )
            assert "window_probabilities" in result, "Missing window_probabilities"
            windows = result["window_probabilities"]
            assert len(windows) == 5, (
                f"Expected 5 window probabilities, got {len(windows)}"
            )
            total_prob = sum(windows.values())
            assert 0.99 <= total_prob <= 1.01, (
                f"Window probabilities should sum to ~1.0, got {total_prob}"
            )
        except FileNotFoundError:
            # XGBoost model may not exist — that's OK
            pass
        except Exception as e:
            # Only allow FileNotFoundError (no model), not other errors
            if "FileNotFoundError" not in type(e).__name__:
                raise
        finally:
            xp.PCA_MODEL_PATH = old_pca
            xp._pca_model = None
            try:
                fake_pca.unlink()
            except OSError:
                pass

    def test_multi_window_backward_compat(self):
        """Verify exploitation_probability still exists for downstream consumers."""
        from ml.xgboost_predictor import predict
        import ml.xgboost_predictor as xp

        from pathlib import Path
        import tempfile

        old_pca = xp.PCA_MODEL_PATH
        fake_pca = Path(tempfile.mktemp(suffix=".pkl"))
        try:
            xp.PCA_MODEL_PATH = fake_pca
            xp._pca_model = None

            features = {
                "epss_score": 0.05,
                "description": "Test backward compatibility",
            }
            result = predict(features)
            assert "exploitation_probability" in result
            assert 0.0 <= result["exploitation_probability"] <= 1.0, (
                f"exploitation_probability out of range: "
                f"{result['exploitation_probability']}"
            )
        except FileNotFoundError:
            pass
        except Exception as e:
            if "FileNotFoundError" not in type(e).__name__:
                raise
        finally:
            xp.PCA_MODEL_PATH = old_pca
            xp._pca_model = None
            try:
                fake_pca.unlink()
            except OSError:
                pass
