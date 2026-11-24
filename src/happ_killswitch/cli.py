"""Command line interface."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys

from .config import ConfigError, default_config_path, load_config
from .controller import activate_vpn, validate_profile
from .firewall import Nftables
from .profile import ProfileError


def _require_root() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("Команда изменяет правила firewall. Запустите её с sudo.")


def _is_ubuntu() -> bool:
    try:
        return platform.freedesktop_os_release().get("ID", "").lower() == "ubuntu"
    except (AttributeError, OSError):
        return False


def _nft() -> Nftables:
    executable = shutil.which("nft")
    if not executable:
        raise RuntimeError("nftables не установлен (не найдена команда nft)")
    return Nftables(executable)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="happ-killswitch", description="Аварийный сетевой выключатель для Happ в Ubuntu", add_help=False)
    parser._positionals.title = "команды"
    parser._optionals.title = "параметры"
    parser.add_argument("-h", "--help", action="help", help="Показать эту справку и выйти")
    parser.add_argument("--config", help="Путь к файлу конфигурации TOML", default=None)
    parser.add_argument("command", nargs="?", default="tui", choices=("setup", "check", "status", "on", "lock", "off", "watch", "tui"), help="Команда: setup, check, status, on, lock, off, watch или tui")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config_path = args.config or default_config_path()
    try:
        if args.command == "setup":
            from .setup import run_setup
            run_setup(config_path)
            return 0
        if args.command == "check":
            if platform.system() != "Linux" or not _is_ubuntu():
                raise RuntimeError("Эта версия поддерживает только Ubuntu Linux")
            config = load_config(config_path)
            _require_root()
            nft = _nft()
            _, endpoints = validate_profile(config, nft)
            print(f"Проверка пройдена: Ubuntu; профиль прочитан; nftables принял адресов серверов: {len(endpoints)}")
            return 0
        if args.command == "status":
            status_labels = {"OFF": "ВЫКЛЮЧЕНА", "LOCKED": "ПОЛНАЯ БЛОКИРОВКА", "VPN_ONLY": "ТОЛЬКО VPN"}
            print(status_labels.get(_nft().status(), "НЕИЗВЕСТНО"))
            return 0
        if args.command == "watch":
            from .watchdog import run_watchdog
            _require_root()
            config = load_config(config_path)
            run_watchdog(config, _nft())
            return 0
        if args.command in {"on", "lock", "off"}:
            _require_root()
            nft = _nft()
            if args.command == "off":
                nft.remove()
                print("Kill Switch отключён; удалена только таблица happ_killswitch.")
                return 0
            if args.command == "lock":
                nft.apply("lock")
                print("Полная блокировка включена. Исходящий трафик запрещён, кроме loopback.")
                return 0
            config = load_config(config_path)
            _, endpoints = activate_vpn(config, nft)
            print(f"Режим «Только VPN» включён. Разрешённых адресов серверов: {len(endpoints)}. Подключите Happ в режиме TUN и проверьте трафик.")
            return 0
        if args.command == "tui":
            if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() != 0:
                try:
                    load_config(config_path)
                except ConfigError:
                    pass
                else:
                    command = ["sudo", sys.executable, "-m", "happ_killswitch.cli", "--config", str(config_path), "tui"]
                    os.execvp(command[0], command)
            from .tui import run
            run(config_path)
            return 0
    except (ConfigError, ProfileError, PermissionError, RuntimeError, OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
