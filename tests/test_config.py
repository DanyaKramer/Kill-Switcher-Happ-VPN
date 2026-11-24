from pathlib import Path

import pytest

from happ_killswitch.config import ConfigError, load_config


def test_load_valid_config(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text('[vpn]\nsource="vless://abc@example.com:443?type=tcp"\ntun_interface="tun0"\n', encoding="utf-8")
    cfg = load_config(path)
    assert cfg.vpn.source == "vless://abc@example.com:443?type=tcp"
    assert cfg.failure_threshold == 3
    assert cfg.dns_refresh_seconds == 60
    assert cfg.profile_refresh_seconds == 900


def test_load_config_accepts_string_path(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text('[vpn]\nsource="vless://abc@192.0.2.1:443"\ntun_interface="tun0"\n', encoding="utf-8")
    assert load_config(str(path)).vpn.source == "vless://abc@192.0.2.1:443"


@pytest.mark.parametrize("port", [0, 65536, "443", True])
def test_invalid_port_is_rejected(tmp_path: Path, port):
    path = tmp_path / "config.toml"
    path.write_text(f'[vpn]\nserver_host="192.0.2.1"\nserver_port={str(port).lower() if isinstance(port, bool) else repr(port)}\ntun_interface="tun0"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="server_port"):
        load_config(path)


def test_missing_config_has_actionable_message(tmp_path: Path):
    with pytest.raises(ConfigError, match="мастер импорта JSON"):
        load_config(tmp_path / "missing.toml")


def test_legacy_static_config_is_converted_to_profile_source(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text('[vpn]\nserver_host="192.0.2.20"\nserver_port=443\nserver_protocol="tcp"\ntun_interface="tun0"\n', encoding="utf-8")
    assert load_config(path).vpn.source == "vless://legacy@192.0.2.20:443?type=tcp"


def test_plain_http_subscription_url_is_rejected(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text('[vpn]\nsource="http://provider.example/sub"\ntun_interface="tun0"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="vless://"):
        load_config(path)
