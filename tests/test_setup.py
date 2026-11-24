from pathlib import Path

import happ_killswitch.setup as setup
from happ_killswitch.config import AppConfig, VPNConfig, load_config
from happ_killswitch.profile import Server, parse_vless_link, server_as_vless_source
from happ_killswitch.setup import _write_config


def test_imported_server_round_trips_as_safe_vless_profile():
    server = Server("2001:db8::8", 443, "tcp")
    parsed = parse_vless_link(server_as_vless_source(server))
    assert parsed == server


def test_setup_writes_private_config_and_preserves_monitor_settings(tmp_path: Path):
    path = tmp_path / "config.toml"
    previous = AppConfig(VPNConfig("https://provider.example/sub?token=private", "happ-xray"), 5, 4, 75, 1200)
    _write_config(path, server_as_vless_source(Server("node.example", 443, "tcp")), "happ-xray", previous)

    config = load_config(path)
    assert config.vpn.source == "vless://happ-killswitch-import@node.example:443?type=tcp#ImportedFromHapp"
    assert config.vpn.tun_interface == "happ-xray"
    assert config.interval_seconds == 5
    assert config.failure_threshold == 4
    assert config.dns_refresh_seconds == 75
    assert config.profile_refresh_seconds == 1200
    assert "private" not in path.read_text(encoding="utf-8")


def test_setup_accepts_config_path_string(tmp_path: Path, monkeypatch):
    path = tmp_path / "config.toml"
    if hasattr(setup.os, "geteuid"):
        monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(setup, "_choose_json_server", lambda _path: Server("node.example", 443, "tcp"))
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    setup.run_setup(str(path))

    assert load_config(path).vpn.source == "vless://happ-killswitch-import@node.example:443?type=tcp#ImportedFromHapp"
