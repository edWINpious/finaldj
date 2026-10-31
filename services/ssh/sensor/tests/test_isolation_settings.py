"""Guard the project rules this component must keep: no tried passwords, no SOC link yet."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from cowrie_soc.config import NormalizeSection, load_config

SSH_ROOT = Path(__file__).parents[2]
SCRIPT = SSH_ROOT / "cowrie" / "strip_password_logging.py"
SAMPLE = """\
events.dispatch(
    "cowrie.login.success",
    "login attempt [%(username)s/%(password)s] succeeded",
    username=escape_nonprintable(theusername),
    password=escape_nonprintable(thepassword),
)
events.dispatch(
    "cowrie.login.failed",
    "login attempt [%(username)s/%(password)s] failed",
    username=escape_nonprintable(theusername),
    password=escape_nonprintable(thepassword),
)
"""


def strip(monkeypatch: pytest.MonkeyPatch, source: Path, output: Path) -> int:
    spec = importlib.util.spec_from_file_location("strip_password_logging", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(source), str(output)])
    return module.main()


def test_shipped_config_keeps_passwords_out_and_delivery_off() -> None:
    cfg = load_config(SSH_ROOT / "sensor" / "config" / "collector.toml", env={})
    assert cfg.collector.sensor_id == "ssh-01"
    assert cfg.normalize.include_passwords is False
    assert cfg.http.enabled is False


def test_password_capture_is_off_when_the_setting_is_missing() -> None:
    assert NormalizeSection().include_passwords is False


def test_cowrie_reports_the_same_sensor_identity() -> None:
    assert "sensor_name = ssh-01\n" in (SSH_ROOT / "cowrie" / "cowrie.cfg").read_text(encoding="utf-8")


def test_password_is_removed_from_both_login_events(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source, output = tmp_path / "checkers.py", tmp_path / "out" / "checkers.py"
    source.write_text(SAMPLE, encoding="utf-8")
    assert strip(monkeypatch, source, output) == 0
    text = output.read_text(encoding="utf-8")
    assert "password" not in text
    assert text.count("username=escape_nonprintable(theusername),") == 2
    assert '"login attempt [%(username)s] failed"' in text


@pytest.mark.parametrize("broken", [
    SAMPLE.replace("    password=escape_nonprintable(thepassword),\n", "", 1),
    SAMPLE.replace("/%(password)s] failed", "] failed"),
    SAMPLE + 'log("%(password)s")\n',
])
def test_unexpected_cowrie_code_fails_the_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, broken: str,
) -> None:
    source, output = tmp_path / "checkers.py", tmp_path / "out" / "checkers.py"
    source.write_text(broken, encoding="utf-8")
    with pytest.raises(SystemExit):
        strip(monkeypatch, source, output)
    assert not output.exists()


def test_isolated_compose_has_no_soc_link_or_published_port() -> None:
    text = (SSH_ROOT / "docker-compose.isolated.yml").read_text(encoding="utf-8")
    services = text.split("\nservices:\n", 1)[1]
    for forbidden in ("COWRIE_SOC_HTTP", "SOC_INGEST", "http://", "ports:", "lab_net", "ingest_net", "soc_edge"):
        assert forbidden not in services
    assert "network_mode: none" in services
    assert "internal: true" in text
    assert "com.docker.network.bridge.inhibit_ipv4" in text
