"""Fail-closed Chromium sandbox launch-option tests; no browser is started."""

import pytest

from scrapling.engines._browsers._stealth import StealthySession, AsyncStealthySession


@pytest.mark.parametrize("cls", [StealthySession, AsyncStealthySession])
def test_chromium_sandbox_enabled_by_default(cls):
    session = cls()
    assert session._config.chromium_sandbox is True
    assert session._browser_options["chromium_sandbox"] is True
    assert "--no-sandbox" not in session._browser_options["args"]
    assert "--disable-setuid-sandbox" not in session._browser_options["args"]


@pytest.mark.parametrize("cls", [StealthySession, AsyncStealthySession])
def test_insecure_browser_requires_explicit_opt_out(cls):
    session = cls(chromium_sandbox=False)
    assert session._config.chromium_sandbox is False
    assert session._browser_options["chromium_sandbox"] is False


@pytest.mark.parametrize("cls", [StealthySession, AsyncStealthySession])
@pytest.mark.parametrize("flag", [
    "--no-sandbox", "--disable-setuid-sandbox", "--no-sandbox=true",
    "--disable-seccomp-filter-sandbox", "--disable-namespace-sandbox",
    "--disable-gpu-sandbox", "--disable-sandbox",
])
def test_forbid_sandbox_disabling_flags_when_sandbox_is_required(cls, flag):
    with pytest.raises(ValueError, match="sandbox-disabling flags"):
        cls(extra_flags=[flag])


@pytest.mark.parametrize("cls", [StealthySession, AsyncStealthySession])
@pytest.mark.parametrize("override", [
    {"chromium_sandbox": False},
    {"args": ["--no-sandbox"]},
    {"ignore_default_args": ["--disable-features"]},
])
def test_no_implicit_sandbox_override_from_additional_args(cls, override):
    with pytest.raises(ValueError, match="Browser launch options"):
        cls(additional_args=override)


@pytest.mark.parametrize("cls", [StealthySession, AsyncStealthySession])
def test_explicit_legacy_opt_out_can_set_unsafe_flag(cls):
    session = cls(chromium_sandbox=False, extra_flags=["--no-sandbox"])
    assert session._browser_options["chromium_sandbox"] is False
    assert "--no-sandbox" in session._browser_options["args"]
