"""
Tests for the scheduler retraining system.

Covers:
  - Lock mechanism (acquire/release/stale)
  - Drift polling structure
  - Retrain status endpoint
  - No-drift no-action behavior

Uses ``tmp_path``-based lock file isolation and ``unittest.mock.patch``
to avoid shared-state races with parallel test execution.
"""

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest


# ── Fixture: isolate lock file to tmp_path ─────────────────────────────


@pytest.fixture
def _isolated_lock(monkeypatch, tmp_path):
    """Redirect ``scheduler.LOCK_FILE`` to a ``tmp_path``-backed location."""
    import scheduler

    monkeypatch.setattr(scheduler, "LOCK_FILE", tmp_path / ".retrain.lock")


class TestRetrainLockMechanism:
    """Verify lock file prevents concurrent retrains."""

    @pytest.fixture(autouse=True)
    def _use_isolated_lock(self, _isolated_lock):
        pass

    def test_retrain_lock_acquire_release(self):
        """Lock file is created on acquire and removed on release."""
        from scheduler import LOCK_FILE, _acquire_lock, _release_lock

        # Ensure clean state
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()

        try:
            assert not LOCK_FILE.exists()
            _acquire_lock()
            assert LOCK_FILE.exists()

            content = LOCK_FILE.read_text().strip()
            # Should be a valid ISO datetime
            datetime.fromisoformat(content)
        finally:
            _release_lock()
            assert not LOCK_FILE.exists()

    def test_retrain_stale_lock_recycled(self):
        """A lock older than LOCK_STALE_HOURS is recycled (treated as not held)."""
        from scheduler import LOCK_FILE, _is_lock_held, _acquire_lock

        if LOCK_FILE.exists():
            LOCK_FILE.unlink()

        try:
            _acquire_lock()

            # Manually set lock time to 12 hours ago (STALE)
            stale_time = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
            LOCK_FILE.write_text(stale_time)

            # Should be treated as not held (recycled)
            assert not _is_lock_held(), "Stale lock should be recycled"
            # Lock file should have been removed
            assert not LOCK_FILE.exists()
        finally:
            if LOCK_FILE.exists():
                LOCK_FILE.unlink()

    def test_retrain_lock_unparseable_recycled(self):
        """An unparseable lock file is treated as very old and recycled."""
        from scheduler import LOCK_FILE, _is_lock_held

        if LOCK_FILE.exists():
            LOCK_FILE.unlink()

        try:
            LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
            LOCK_FILE.write_text("not-a-valid-datetime")

            # Should be recycled (lock file removed)
            assert not _is_lock_held()
            assert not LOCK_FILE.exists()
        finally:
            if LOCK_FILE.exists():
                LOCK_FILE.unlink()

    def test_retrain_lock_fresh_held(self):
        """A recent lock file is considered held."""
        from scheduler import LOCK_FILE, _is_lock_held, _acquire_lock, _release_lock

        if LOCK_FILE.exists():
            LOCK_FILE.unlink()

        try:
            _acquire_lock()
            assert _is_lock_held(), "Fresh lock should be held"
        finally:
            _release_lock()


@pytest.mark.asyncio
class TestRetrainDriftCheck:
    """Verify poll_drift_status returns expected structure."""

    async def test_poll_drift_returns_dict(self):
        """poll_drift_status should return a dict with expected model names."""
        from scheduler import poll_drift_status

        # Mock get_db at its definition site (database module)
        with patch("database.get_db") as mock_get_db:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_conn.execute.return_value = mock_cursor
            mock_get_db.return_value = mock_conn

            result = await poll_drift_status()

        assert isinstance(result, dict)
        # Should contain all monitored models
        assert "xgboost" in result
        assert "pre_tier" in result
        assert "epss" in result

    async def test_poll_drift_values_are_floats(self):
        """poll_drift_status values should be floats."""
        from scheduler import poll_drift_status

        with patch("database.get_db") as mock_get_db:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_conn.execute.return_value = mock_cursor
            mock_get_db.return_value = mock_conn

            result = await poll_drift_status()

        for name, value in result.items():
            assert isinstance(value, float), (
                f"{name} should be float, got {type(value)}"
            )

    async def test_poll_drift_non_negative(self):
        """PSI values should be non-negative."""
        from scheduler import poll_drift_status

        with patch("database.get_db") as mock_get_db:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_conn.execute.return_value = mock_cursor
            mock_get_db.return_value = mock_conn

            result = await poll_drift_status()

        for name, value in result.items():
            assert value >= 0.0, f"{name} PSI should be >= 0, got {value}"


@pytest.mark.asyncio
class TestRetrainStatusEndpoint:
    """Verify GET /api/system/retrain-status."""

    async def test_retrain_status_returns_200(self, client):
        """GET /api/system/retrain-status should return 200."""
        response = await client.get("/api/system/retrain-status")
        assert response.status_code == 200

    async def test_retrain_status_expected_keys(self, client):
        """Response should contain all expected keys."""
        response = await client.get("/api/system/retrain-status")
        data = response.json()

        expected_keys = {
            "automatic_retraining_enabled",
            "retrain_interval_hours",
            "drift_threshold",
            "lock_held",
            "lock_age_hours",
        }
        missing = expected_keys - set(data.keys())
        assert not missing, f"Missing keys: {missing}"

    async def test_retrain_status_types(self, client):
        """Response values should have correct types."""
        response = await client.get("/api/system/retrain-status")
        data = response.json()

        assert isinstance(data["retrain_interval_hours"], int)
        assert isinstance(data["drift_threshold"], float)
        assert isinstance(data["lock_held"], bool)
        # lock_age_hours can be None or float
        assert data["lock_age_hours"] is None or isinstance(
            data["lock_age_hours"], float
        )


class TestAutomaticRetrainingEnabledDefault:
    """Verify the default-off behaviour of AUTOMATIC_RETRAINING_ENABLED."""

    def test_automatic_retraining_disabled_by_default(self):
        """AUTOMATIC_RETRAINING_ENABLED should be False by default."""
        from scheduler import AUTOMATIC_RETRAINING_ENABLED

        assert AUTOMATIC_RETRAINING_ENABLED is False


@pytest.mark.asyncio
class TestRetrainNoDriftNoAction:
    """When no drift is detected, no retrain should be triggered."""

    @patch("scheduler.poll_drift_status")
    async def test_no_drift_no_retrain(self, mock_poll):
        """check_drift_and_retrain should not retrain when all PSI < threshold."""
        from scheduler import check_drift_and_retrain, RETRAIN_DRIFT_THRESHOLD

        # Set drift values below threshold
        safe_psi = max(0.0, RETRAIN_DRIFT_THRESHOLD - 0.05)
        mock_poll.return_value = {
            "xgboost": safe_psi,
            "pre_tier": safe_psi,
            "epss": safe_psi,
        }

        with (
            patch("scheduler.retrain_model") as mock_retrain,
            patch("scheduler.AUTOMATIC_RETRAINING_ENABLED", True),
        ):
            await check_drift_and_retrain()
            # Verify retrain_model was NOT called
            mock_retrain.assert_not_called()

    @patch("scheduler.poll_drift_status")
    async def test_drift_triggers_retrain(self, mock_poll):
        """check_drift_and_retrain should retrain when a model exceeds threshold."""
        from scheduler import check_drift_and_retrain, RETRAIN_DRIFT_THRESHOLD

        # Set one model above threshold
        high_psi = RETRAIN_DRIFT_THRESHOLD + 0.1
        mock_poll.return_value = {
            "xgboost": high_psi,
            "pre_tier": 0.0,
            "epss": 0.0,
        }

        with (
            patch("scheduler.retrain_model", new_callable=AsyncMock) as mock_retrain,
            patch("scheduler.AUTOMATIC_RETRAINING_ENABLED", True),
        ):
            mock_retrain.return_value = {
                "status": "success",
                "model": "xgboost",
                "metrics": {},
            }
            await check_drift_and_retrain()
            # Verify retrain_model was called for xgboost
            mock_retrain.assert_called_once_with("xgboost")

    @patch("scheduler.poll_drift_status")
    async def test_retrain_not_called_when_disabled(self, mock_poll):
        """check_drift_and_retrain should NOT retrain even with drift when disabled."""
        from scheduler import check_drift_and_retrain, RETRAIN_DRIFT_THRESHOLD

        # Set one model above threshold
        high_psi = RETRAIN_DRIFT_THRESHOLD + 0.1
        mock_poll.return_value = {
            "xgboost": high_psi,
            "pre_tier": 0.0,
            "epss": 0.0,
        }

        with (
            patch("scheduler.retrain_model", new_callable=AsyncMock) as mock_retrain,
            patch("scheduler.AUTOMATIC_RETRAINING_ENABLED", False),
        ):
            await check_drift_and_retrain()
            # Verify retrain_model was NOT called despite high drift
            mock_retrain.assert_not_called()


@pytest.mark.asyncio
class TestRetrainModelFunction:
    """Verify retrain_model behavior with mocks."""

    @patch("scheduler._is_lock_held")
    async def test_retrain_model_skipped_when_lock_held(self, mock_lock):
        """retrain_model should skip when lock is held."""
        from scheduler import retrain_model

        mock_lock.return_value = True

        with patch("scheduler._get_lock_age") as mock_age:
            mock_age.return_value = 2.0
            result = await retrain_model("xgboost")

        assert result["status"] == "skipped"
        assert result["reason"] == "lock_held"

    @patch("scheduler._is_lock_held")
    async def test_retrain_model_unknown_model(self, mock_lock):
        """retrain_model should error on unknown model name."""
        from scheduler import retrain_model

        mock_lock.return_value = False

        with patch("scheduler._acquire_lock"), patch("scheduler._release_lock"):
            result = await retrain_model("nonexistent_model")

        assert result["status"] == "error"
        assert "Unknown model" in result.get("error", "")


class TestModelRegistryHelpers:
    """Verify model registry helper functions."""

    def test_get_current_model_metrics_no_file(self):
        """get_current_model_metrics should return None for missing registry."""
        from scheduler import get_current_model_metrics

        with patch("scheduler.XGBOOST_REGISTRY") as mock_path:
            mock_path.exists.return_value = False
            result = get_current_model_metrics("xgboost")
            assert result is None

    def test_get_current_model_metrics_unknown_model(self):
        """get_current_model_metrics should return None for unknown model."""
        from scheduler import get_current_model_metrics

        result = get_current_model_metrics("nonexistent")
        assert result is None

    def test_get_current_model_metrics_reads_active(self):
        """get_current_model_metrics should return metrics of active version."""
        from scheduler import get_current_model_metrics
        import scheduler as sched_mod

        test_registry = {
            "active_version": "v2",
            "versions": [
                {"version": "v1", "metrics": {"roc_auc": 0.90}, "active": False},
                {"version": "v2", "metrics": {"roc_auc": 0.95}, "active": True},
            ],
        }

        # Write temp registry
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_registry, f)
            temp_path = f.name

        try:
            # Swap the module-level path
            original_path = sched_mod.XGBOOST_REGISTRY
            sched_mod.XGBOOST_REGISTRY = Path(temp_path)

            try:
                result = get_current_model_metrics("xgboost")
                assert result is not None
                assert result["roc_auc"] == 0.95
            finally:
                sched_mod.XGBOOST_REGISTRY = original_path
        finally:
            os.unlink(temp_path)


@pytest.mark.asyncio
class TestDriftCheckStructure:
    """Verify drift check function structure."""

    async def test_retain_drift_check_structure(self):
        """poll_drift_status returns expected dict with model keys."""
        from scheduler import poll_drift_status

        with patch("database.get_db") as mock_get_db:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.fetchall.return_value = []
            mock_conn.execute.return_value = mock_cursor
            mock_get_db.return_value = mock_conn

            result = await poll_drift_status()

        # Should have keys for all monitored models
        assert "xgboost" in result
        assert "pre_tier" in result
        assert "epss" in result


@pytest.mark.asyncio
class TestRetrainCheckDriftLogging:
    """Verify check_drift_and_retrain logs appropriately."""

    @patch("scheduler.poll_drift_status")
    async def test_retrain_check_drift_logs_summary(self, mock_poll, caplog):
        """check_drift_and_retrain should log drift summary."""
        from scheduler import check_drift_and_retrain

        mock_poll.return_value = {
            "xgboost": 0.02,
            "pre_tier": 0.03,
            "epss": 0.01,
        }

        import logging

        caplog.set_level(logging.INFO, logger="triagemate.scheduler")

        with (
            patch("scheduler.retrain_model", new_callable=AsyncMock),
            patch("scheduler.AUTOMATIC_RETRAINING_ENABLED", True),
        ):
            await check_drift_and_retrain()

        # Should log the drift summary
        assert any("Drift check:" in record.message for record in caplog.records)
        assert any(
            "No retraining needed" in record.message for record in caplog.records
        )
