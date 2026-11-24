"""Configuration loading and validation."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows development host
    pwd = None

if sys.version_info >= (3, 11):
    import tomllib
else:  # Ubuntu 22.04 ships Python 3.10
    import tomli as tomllib


class ConfigError(ValueError):
    """Invalid or missing application configuration."""


DEFAULT_CONFIG = Path.home() / ".config/happ-killswitch/config.toml"


@dataclass(frozen=True)
class VPNConfig:
    source: str
    tun_interface: str

@dataclass(frozen=True)
class AppConfig:
    vpn: VPNConfig
    interval_seconds: int = 3
    failure_threshold: int = 3
    dns_refresh_seconds: int = 60
    profile_refresh_seconds: int = 900


def load_config(path: Path | str = DEFAULT_CONFIG) -> AppConfig:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Файл конфигурации не найден: {path}. Запустите мастер импорта JSON из Happ.")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Не удалось прочитать конфигурацию {path}: {exc}") from exc
    vpn = raw.get("vpn", {})
    monitor = raw.get("monitor", {})
    source = vpn.get("source")
    interface = vpn.get("tun_interface")
    if source is None:
        # Keep configurations from the initial MVP usable while switching to profile sources.
        host = vpn.get("server_host")
        port = vpn.get("server_port")
        protocol = vpn.get("server_protocol", "tcp")
        if not isinstance(host, str) or not host.strip():
            raise ConfigError("В vpn.source должна быть ссылка VLESS или адрес HTTPS-подписки")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ConfigError("vpn.server_port должен быть целым числом от 1 до 65535")
        if protocol not in {"tcp", "udp"}:
            raise ConfigError("vpn.server_protocol должен быть 'tcp' или 'udp'")
        authority = f"[{host.strip()}]" if ":" in host and not host.startswith("[") else host.strip()
        transport = "kcp" if protocol == "udp" else "tcp"
        source = f"vless://legacy@{authority}:{port}?type={transport}"
    if not isinstance(source, str) or not source.strip():
        raise ConfigError("В vpn.source должна быть ссылка VLESS или адрес HTTPS-подписки")
    if not source.lower().startswith(("vless://", "https://")):
        raise ConfigError("vpn.source должен начинаться с vless:// или https://")
    if not isinstance(interface, str) or not interface or len(interface.encode()) > 15 or any(c.isspace() for c in interface):
        raise ConfigError("vpn.tun_interface должен содержать имя сетевого интерфейса Linux длиной не более 15 байт")
    interval = monitor.get("interval_seconds", 3)
    threshold = monitor.get("failure_threshold", 3)
    dns_refresh = monitor.get("dns_refresh_seconds", 60)
    profile_refresh = monitor.get("profile_refresh_seconds", 900)
    if not isinstance(interval, int) or interval < 1:
        raise ConfigError("monitor.interval_seconds должен быть положительным целым числом")
    if not isinstance(threshold, int) or threshold < 1:
        raise ConfigError("monitor.failure_threshold должен быть положительным целым числом")
    if not isinstance(dns_refresh, int) or dns_refresh < 5:
        raise ConfigError("monitor.dns_refresh_seconds должен быть целым числом не меньше 5")
    if not isinstance(profile_refresh, int) or profile_refresh < 30:
        raise ConfigError("monitor.profile_refresh_seconds должен быть целым числом не меньше 30")
    return AppConfig(VPNConfig(source.strip(), interface), interval, threshold, dns_refresh, profile_refresh)


def default_config_path() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if not config_home and pwd is not None and os.environ.get("SUDO_USER"):
        try:
            config_home = str(Path(pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir) / ".config")
        except KeyError:
            pass
    return Path(config_home or (Path.home() / ".config")) / "happ-killswitch/config.toml"


def profile_cache_path() -> Path:
    return Path(os.environ.get("HAPP_KILLSWITCH_CACHE_PATH", "/var/lib/happ-killswitch/profile-cache.json"))


