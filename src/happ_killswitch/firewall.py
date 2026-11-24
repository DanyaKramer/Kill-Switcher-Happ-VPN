"""nftables ruleset generation and narrow table management."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from dataclasses import dataclass

TABLE = "happ_killswitch"


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int
    protocol: str

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError("Адрес сервера VPN должен быть IP-адресом") from exc
        if not 1 <= self.port <= 65535 or self.protocol not in {"tcp", "udp"}:
            raise ValueError("Некорректные параметры сервера VPN")


def render_rules(mode: str, endpoints: tuple[Endpoint, ...] = (), tun_interface: str | None = None, *, replace_existing: bool = False) -> str:
    if mode not in {"vpn", "lock"}:
        raise ValueError("Режим должен быть 'vpn' или 'lock'")
    # Never broadly allow established flows: that could preserve a direct
    # connection which was already open when protection was enabled.
    lines = ([f"delete table inet {TABLE}"] if replace_existing else [])
    lines.extend([f"table inet {TABLE} {{", "  chain output {", "    type filter hook output priority -150; policy drop;", "    oifname \"lo\" accept"])
    if mode == "vpn":
        if not endpoints:
            raise ValueError("Для режима VPN нужен хотя бы один определённый адрес сервера")
        for endpoint in endpoints:
            family_key = "ip" if ipaddress.ip_address(endpoint.address).version == 4 else "ip6"
            lines.append(f"    {family_key} daddr {endpoint.address} {endpoint.protocol} dport {endpoint.port} accept")
        if tun_interface:
            if len(tun_interface.encode()) > 15 or any(ch in tun_interface for ch in '"\\\n'):
                raise ValueError("Некорректное имя TUN-интерфейса")
            lines.append(f'    oifname "{tun_interface}" accept')
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


class Nftables:
    def __init__(self, executable: str = "nft") -> None:
        self.executable = executable

    def apply(self, mode: str, endpoints: tuple[Endpoint, ...] = (), tun_interface: str | None = None) -> None:
        existing = self._tables()
        rules = render_rules(mode, endpoints, tun_interface, replace_existing=("inet", TABLE) in existing)
        result = subprocess.run([self.executable, "-f", "-"], input=rules, text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Не удалось применить правила nftables")

    def validate(self, mode: str, endpoints: tuple[Endpoint, ...] = (), tun_interface: str | None = None) -> None:
        existing = self._tables()
        rules = render_rules(mode, endpoints, tun_interface, replace_existing=("inet", TABLE) in existing)
        result = subprocess.run([self.executable, "--check", "-f", "-"], input=rules, text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "nftables отклонил сформированные правила")

    def remove(self) -> None:
        if ("inet", TABLE) not in self._tables():
            return
        result = subprocess.run([self.executable, "delete", "table", "inet", TABLE], text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Не удалось удалить таблицу приложения из nftables")

    def status(self) -> str:
        if ("inet", TABLE) not in self._tables():
            return "OFF"
        result = subprocess.run([self.executable, "list", "table", "inet", TABLE], text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Не удалось получить состояние nftables")
        return "LOCKED" if "policy drop" in result.stdout and "daddr" not in result.stdout else "VPN_ONLY"

    def _tables(self) -> set[tuple[str, str]]:
        result = subprocess.run([self.executable, "-j", "list", "tables"], text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Не удалось просмотреть таблицы nftables")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"nft вернул некорректный JSON: {exc}") from exc
        return {
            (entry["table"]["family"], entry["table"]["name"])
            for entry in data.get("nftables", [])
            if isinstance(entry, dict) and isinstance(entry.get("table"), dict)
        }
