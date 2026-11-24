"""Quick-start Textual dashboard for Happ Kill Switch."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

try:
    import pwd
except ImportError:  # Windows development host
    pwd = None

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Static

from .cli import _nft
from .config import ConfigError, load_config
from .controller import activate_vpn
from .watchdog import tun_exists


class ConfirmAction(ModalScreen[bool]):
    CSS = """
    ConfirmAction { align: center middle; }
    #confirm-box { width: 64; height: auto; border: round $warning; background: $surface; padding: 1 2; }
    #confirm-message { height: auto; margin-bottom: 1; }
    #confirm-buttons { height: auto; align-horizontal: right; }
    """

    def __init__(self, title: str, message: str, action: str, variant: str) -> None:
        super().__init__()
        self.title = title
        self.message = message
        self.action = action
        self.variant = variant

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static(f"[b]{self.title}[/b]\n\n{self.message}", id="confirm-message")
            with Horizontal(id="confirm-buttons"):
                yield Button("Отмена", id="cancel")
                yield Button(self.action, id="confirm", variant=self.variant)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")


class KillSwitchApp(App[None]):
    TITLE = "Happ Kill Switch"
    SUB_TITLE = "Управление сетевой защитой VPN"
    CSS = """
    Screen { align: center top; }
    #layout { width: 94%; max-width: 100; height: auto; border: round $primary; padding: 0 1; margin-top: 1; }
    #brand { height: 1; content-align: center middle; text-style: bold; color: $text; }
    #state { height: 3; content-align: center middle; text-style: bold; border: round $accent; margin-bottom: 0; }
    #details { height: auto; min-height: 1; margin: 0 1; }
    #notice { height: auto; min-height: 1; color: $text-muted; margin: 0 1; }
    #actions { height: 3; align-horizontal: center; }
    #actions Button { margin: 0 1; min-width: 15; }
    #actions Button:disabled { color: $text-muted; background: $surface; }
    #lower-actions { height: 3; align-horizontal: center; }
    #lower-actions Button { margin: 0 1; min-width: 17; }
    """
    BINDINGS = [
        ("r", "refresh", "Обновить"),
        ("s", "setup", "Настроить"),
        ("q", "quit", "Выход"),
    ]

    def __init__(self, config_path: Path | str) -> None:
        super().__init__()
        self.config_path = Path(config_path)
        self.configured = self.config_path.is_file()
        self._last_state = "UNKNOWN"
        self._state_widget: Static | None = None
        self._details_widget: Static | None = None
        self._notice_widget: Static | None = None
        self._buttons: dict[str, Button] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="layout"):
            yield Static("HAPP KILL SWITCH", id="brand")
            yield Static("Проверка сетевой защиты…", id="state")
            yield Static("", id="details")
            yield Static("", id="notice")
            with Horizontal(id="actions"):
                yield Button("Только VPN", id="on", variant="success")
                yield Button("Блокировать", id="lock", variant="warning")
                yield Button("Отключить", id="off", variant="error")
            with Horizontal(id="lower-actions"):
                yield Button("Импорт JSON", id="setup")
                yield Button("Запуск от администратора", id="elevate")
        yield Footer()

    def on_mount(self) -> None:
        self._state_widget = self.query_one("#state", Static)
        self._details_widget = self.query_one("#details", Static)
        self._notice_widget = self.query_one("#notice", Static)
        self._buttons = {name: self.query_one(f"#{name}", Button) for name in ("on", "lock", "off", "setup", "elevate")}
        self.refresh_status()
        self.set_interval(2.0, self.refresh_status)

    def refresh_status(self) -> None:
        if self._state_widget is None or self._details_widget is None or self._notice_widget is None:
            return
        details: list[str] = []
        try:
            self._last_state = _nft().status()
            labels = {"OFF": "ВЫКЛЮЧЕНА", "LOCKED": "ПОЛНАЯ БЛОКИРОВКА", "VPN_ONLY": "ТОЛЬКО VPN"}
            self._state_widget.update(f"Защита: {labels.get(self._last_state, self._last_state)}")
        except Exception as exc:
            self._last_state = "UNKNOWN"
            if self._is_root():
                self._state_widget.update("Состояние защиты недоступно")
                details.append(f"Ошибка firewall: {exc}")
            else:
                self._state_widget.update("Нужны права администратора")
        self.configured = self.config_path.is_file()
        notice = ""
        if self.configured:
            try:
                config = load_config(self.config_path)
                tunnel = "UP" if tun_exists(config.vpn.tun_interface) else "not found"
                details.append(f"Профиль: {self._profile_label(config.vpn.source)}")
                details.append(f"TUN-интерфейс Happ ({config.vpn.tun_interface}): {self._tunnel_label(tunnel)}")
                if self._last_state == "VPN_ONLY":
                    notice = (
                        "TUN поднят. Проверьте внешний IP, чтобы убедиться, что трафик идёт через VPN."
                        if tunnel == "UP"
                        else "TUN не найден: исходящий трафик заблокирован до подключения Happ."
                    )
                elif self._last_state == "LOCKED":
                    notice = "Весь исходящий трафик, кроме loopback, заблокирован. Для восстановления используйте консоль VMware."
                else:
                    notice = "Защита выключена. Подключите Happ в режиме TUN, затем включите режим «Только VPN»."
            except Exception as exc:
                self.configured = False
                details.append(f"Ошибка конфигурации: {exc}")
                notice = "Повторите импорт JSON из Happ."
        else:
            details.append("Конфигурация сервера не найдена.")
            notice = (
                "Для первой настройки закройте панель и запустите её без sudo."
                if self._is_root()
                else "Для начала импортируйте JSON-конфигурацию сервера из Happ."
            )

        if self._last_state == "UNKNOWN":
            if self._is_root():
                notice += " Проверьте установку nftables."
            else:
                notice = "Для просмотра состояния и управления запустите панель с правами администратора."
        self._details_widget.update("\n".join(details))
        self._notice_widget.update(notice)
        is_root = self._is_root()
        self._buttons["on"].disabled = not (self.configured and is_root)
        self._buttons["lock"].disabled = not is_root
        self._buttons["off"].disabled = not is_root
        setup_owner = self._setup_owner() if is_root else None
        self._buttons["setup"].disabled = is_root and setup_owner is None
        self._buttons["setup"].label = "Импортировать JSON от пользователя" if is_root and setup_owner else "Импорт JSON"
        self._buttons["elevate"].display = not is_root

    @staticmethod
    def _profile_label(source: str) -> str:
        if source.startswith("vless://happ-killswitch-import@"):
            return "Импорт из JSON Happ"
        if source.startswith("https://"):
            return "Подписка VLESS по HTTPS"
        return "Ссылка VLESS"

    @staticmethod
    def _tunnel_label(state: str) -> str:
        return "поднят" if state == "UP" else "не найден"

    @staticmethod
    def _is_root() -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def _setup_owner(self) -> str | None:
        """Return the non-root owner of the config, suitable for editing it."""
        if pwd is None:
            return None
        try:
            owner = pwd.getpwuid(self.config_path.stat().st_uid)
        except (OSError, KeyError):
            return None
        return owner.pw_name if owner.pw_uid != 0 else None

    def action_refresh(self) -> None:
        self.refresh_status()

    def action_setup(self) -> None:
        self._run_setup()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id
        if action == "setup":
            self._run_setup()
        elif action == "elevate":
            self._run_elevated()
        elif action in {"on", "lock", "off"}:
            if not self._is_root():
                self.notify("Для изменения сетевых правил нужны права администратора.", severity="warning", timeout=8)
                return
            messages = {
                "on": ("Включить режим «Только VPN»?", "Будут разрешены только сервер VLESS и трафик через TUN Happ. SSH может отключиться.", "Включить VPN-защиту", "success"),
                "lock": ("Заблокировать весь трафик?", "Будет заблокирован весь исходящий трафик, включая VPN и SSH.", "Заблокировать всё", "warning"),
                "off": ("Отключить Kill Switch?", "Таблица firewall будет удалена, обычный исходящий трафик снова станет доступен.", "Отключить защиту", "error"),
            }
            title, message, label, variant = messages[action]
            self.push_screen(ConfirmAction(title, message, label, variant), lambda confirmed: self._perform_action(action) if confirmed else None)

    def _run_setup(self) -> None:
        if self._is_root():
            owner = self._setup_owner()
            if owner is None:
                self.notify("Не удалось определить владельца конфига. Запустите импорт из учётной записи пользователя.", severity="warning", timeout=10)
                return
            command = [
                "runuser", "-u", owner, "--", sys.executable, "-m", "happ_killswitch.cli",
                "--config", str(self.config_path), "setup",
            ]
            try:
                with self.suspend():
                    result = subprocess.run(command, check=False)
            except OSError as exc:
                self.notify(f"Не удалось запустить настройку от имени {owner}: {exc}", severity="error", timeout=10)
                self.refresh(layout=True, repaint=True)
                return
            if result.returncode == 0:
                self._restart_dashboard()
            else:
                self.notify(f"Настройка завершилась с кодом {result.returncode}", severity="error", timeout=10)
                self.refresh(layout=True, repaint=True)
            return
        from .setup import run_setup

        setup_complete = False
        try:
            with self.suspend():
                run_setup(self.config_path)
            setup_complete = True
            self.notify("Настройка завершена", severity="information")
        except KeyboardInterrupt:
            self.notify("Настройка отменена", severity="warning")
        except Exception as exc:
            self.notify(str(exc), severity="error", timeout=10)
        if setup_complete:
            # Re-exec creates a clean terminal screen and transitions to the
            # administrator dashboard in one authorization prompt.
            self._run_elevated()
        self.refresh(layout=True, repaint=True)
        self.refresh_status()

    def _restart_dashboard(self) -> None:
        command = [sys.executable, "-m", "happ_killswitch.cli", "--config", str(self.config_path), "tui"]
        try:
            with self.suspend():
                os.execv(command[0], command)
        except OSError as exc:
            self.notify(f"Не удалось перезапустить панель: {exc}", severity="error", timeout=10)
            self.refresh(layout=True, repaint=True)

    def _run_elevated(self) -> None:
        if not self.config_path.is_file():
            self.notify("Сначала импортируйте JSON-конфигурацию без sudo.", severity="warning")
            return
        command = ["sudo", sys.executable, "-m", "happ_killswitch.cli", "--config", str(self.config_path), "tui"]
        try:
            with self.suspend():
                os.execvp(command[0], command)
        except OSError as exc:
            self.notify(f"Не удалось запустить панель с правами администратора: {exc}", severity="error", timeout=8)
        self.refresh_status()

    def _perform_action(self, action: str) -> None:
        try:
            nft = _nft()
            if action == "off":
                nft.remove()
            elif action == "lock":
                nft.apply("lock")
            else:
                config = load_config(self.config_path)
                activate_vpn(config, nft)
            labels = {"on": "Режим «Только VPN» включён", "lock": "Полная блокировка включена", "off": "Защита отключена"}
            self.notify(labels[action], severity="information")
        except Exception as exc:
            self.notify(str(exc), severity="error", timeout=10)
        self.refresh_status()


def run(config_path: Path | str) -> None:
    KillSwitchApp(config_path).run()
