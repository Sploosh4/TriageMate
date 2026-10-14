from types import SimpleNamespace

import pytest

from ci_browser_packages import install, PACKAGES


def test_cached_install_does_not_fetch_even_with_permission():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    install(allow_downloads=True, run=run)
    assert len(calls) == 1
    assert "--no-download" in calls[0]
    assert "--no-remove" in calls[0]
    assert calls[0][-len(PACKAGES) :] == list(PACKAGES)


def test_failed_offline_install_never_fetches_without_flag():
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=100)

    with pytest.raises(RuntimeError, match="--allow-downloads"):
        install(allow_downloads=False, run=run)
    assert len(calls) == 1 and "--no-download" in calls[0]


def test_explicit_flag_permits_only_same_packages_after_cache_attempt():
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs["check"]))
        return SimpleNamespace(returncode=100 if len(calls) == 1 else 0)

    install(allow_downloads=True, run=run)
    assert len(calls) == 2
    assert "--no-download" in calls[0][0]
    assert "--no-download" not in calls[1][0]
    assert calls[1][1] is True
    assert calls[0][0][-len(PACKAGES) :] == calls[1][0][-len(PACKAGES) :]
