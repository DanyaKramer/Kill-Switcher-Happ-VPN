"""Interactive first-run profile setup."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from .config import AppConfig, ConfigError, load_config
from .profile import parse_json_config, server_as_vless_source


def _editor_command() -> list[str]:
    command = shlex.split(os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano")
    if not command or shutil.which(command[0]) is None:
        raise RuntimeError("Редактор nano не найден. Установите его командой: sudo apt install nano")
    return command


def _read_happ_json(directory: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="happ-killswitch-", dir=directory) as temporary_directory:
        path = Path(temporary_directory) / "profile.json"
        path.touch(mode=0o600)
        print("Вставьте в редактор JSON-конфигурацию, скопированную из Happ.")
        print("Вставка: Ctrl+Shift+V. Сохранить: Ctrl+O, Enter. Выйти: Ctrl+X.")
        result = subprocess.run(_editor_command() + [str(path)], check=False)
        if result.returncode:
            raise RuntimeError("Редактор завершился с ошибкой; импорт отменён")
        return path.read_text(encoding="utf-8")


def _choose_json_server(config_path: Path):
    text = _read_happ_json(config_path.parent)
    servers = parse_json_config(text)
    print("В JSON найдены серверы VLESS:")
    for index, server in enumerate(servers, start=1):
        print(f"  {index}. {server.host}:{server.port}/{server.protocol}")
    if len(servers) == 1:
        return servers[0]
    while True:
        choice = input(f"Выберите сервер, подключённый в Happ [1–{len(servers)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(servers):
            return servers[int(choice) - 1]
        print("Введите номер одного из найденных серверов.")


def _existing_settings(path: Path) -> tuple[str, AppConfig | None]:
    if not path.exists():
        return "happ-xray", None
    try:
        config = load_config(path)
    except ConfigError:
        return "happ-xray", None
    return config.vpn.tun_interface, config


def _write_config(path: Path, source: str, interface: str, previous: AppConfig | None) -> None:
    interval = previous.interval_seconds if previous else 3
    threshold = previous.failure_threshold if previous else 3
    dns_refresh = previous.dns_refresh_seconds if previous else 60
    profile_refresh = previous.profile_refresh_seconds if previous else 900
    content = (
        "[vpn]\n"
        f"source = {json.dumps(source, ensure_ascii=False)}\n"
        f"tun_interface = {json.dumps(interface)}\n\n"
        "[monitor]\n"
        f"interval_seconds = {interval}\n"
        f"failure_threshold = {threshold}\n"
        f"dns_refresh_seconds = {dns_refresh}\n"
        f"profile_refresh_seconds = {profile_refresh}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def run_setup(config_path: Path | str) -> None:
    """Set up the profile without root; firewall commands remain separately privileged."""
    config_path = Path(config_path)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise PermissionError("Запустите настройку без sudo, чтобы конфиг и nano принадлежали вашему пользователю")
    interface, previous = _existing_settings(config_path)
    print("Настройка Happ Kill Switch: импорт JSON-конфигурации сервера из Happ.")
    server = _choose_json_server(config_path)
    source = server_as_vless_source(server)
    answer = input(f"Имя TUN-интерфейса Happ [{interface}]: ").strip()
    if answer:
        interface = answer
    if not interface or len(interface.encode()) > 15 or any(char.isspace() for char in interface):
        raise ConfigError("Имя TUN-интерфейса должно быть именем Linux длиной не более 15 байт")
    _write_config(config_path, source, interface, previous)
    print(f"Конфигурация сохранена: {config_path} (права доступа 0600).")
    print("JSON обработан локально и удалён. Сохранены только адрес, порт и транспорт выбранного сервера.")

