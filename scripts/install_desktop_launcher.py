"""Install a per-user Ubuntu application-menu launcher."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APPLICATIONS_DIR = Path.home() / ".local/share/applications"
DESKTOP_FILE = "happ-killswitch.desktop"


def find_app_command() -> Path:
    candidates: list[Path] = []
    located = shutil.which("happ-killswitch")
    if located:
        candidates.append(Path(located))
    candidates.extend(
        [
            PROJECT_ROOT / ".venv/bin/happ-killswitch",
            Path.home() / ".local/bin/happ-killswitch",
            Path("/usr/local/bin/happ-killswitch"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise RuntimeError(
        "Команда happ-killswitch не найдена. Сначала установите проект через pip в .venv или в системный PATH."
    )


def _desktop_quote(value: str) -> str:
    escaped = value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")
    return f'"{escaped}"'


def make_desktop_entry(app_command: Path, terminal_command: str) -> str:
    return "\n".join(
        [
            "[Desktop Entry]",
            "Version=1.0",
            "Type=Application",
            "Name=Happ — сетевой выключатель",
            "GenericName=Сетевая защита VPN",
            "Comment=Управление защитой сетевого соединения Happ",
            f"Exec={_desktop_quote(terminal_command)} -- {_desktop_quote(str(app_command))}",
            "Icon=utilities-terminal",
            "Terminal=false",
            "Categories=Network;Utility;",
            "StartupNotify=true",
            "",
        ]
    )


def install_launcher(
    applications_dir: Path = APPLICATIONS_DIR,
    app_command: Path | None = None,
    terminal_command: str | None = None,
) -> Path:
    app_command = app_command or find_app_command()
    terminal_command = terminal_command or shutil.which("gnome-terminal")
    if not terminal_command:
        raise RuntimeError("Не найден GNOME Terminal. Установите пакет gnome-terminal.")
    applications_dir.mkdir(parents=True, exist_ok=True)
    target = applications_dir / DESKTOP_FILE
    target.write_text(make_desktop_entry(app_command, terminal_command), encoding="utf-8")
    target.chmod(0o644)
    update_database = shutil.which("update-desktop-database")
    if update_database:
        subprocess.run([update_database, str(applications_dir)], check=False, capture_output=True)
    return target


def main() -> int:
    try:
        target = install_launcher()
    except (OSError, RuntimeError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    print(f"Ярлык установлен: {target}")
    print("Найдите в меню приложений пункт «Happ — сетевой выключатель».")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
