"""Fail-closed TUN presence watchdog."""

from __future__ import annotations

import signal
import time
from pathlib import Path

from .config import AppConfig, profile_cache_path
from .firewall import Nftables
from .profile import ProfileError, load_profile, read_profile_cache, resolve_servers, write_profile_cache


class TunLossGuard:
    """Count consecutive missing-interface observations."""

    def __init__(self, threshold: int) -> None:
        if threshold < 1:
            raise ValueError("Порог срабатывания должен быть положительным")
        self.threshold = threshold
        self.failures = 0

    def observe(self, present: bool) -> bool:
        self.failures = 0 if present else self.failures + 1
        return self.failures >= self.threshold


def tun_exists(interface: str, sys_class_net: Path = Path("/sys/class/net")) -> bool:
    return (sys_class_net / interface).exists()


def run_watchdog(config: AppConfig, nft: Nftables) -> None:
    """Monitor TUN presence and refresh provider/DNS endpoint addresses.

    This process is intended to be supervised independently from Happ. It never
    unlocks networking automatically. It refreshes profile data only while the
    VPN-only policy is active and the configured TUN exists. Ctrl-C leaves the
    current kernel rules in place.
    """
    guard = TunLossGuard(config.failure_threshold)
    stopping = False
    try:
        servers, endpoints = read_profile_cache(config.vpn.source, profile_cache_path())
    except ProfileError:
        servers, endpoints = (), ()
    refresh_failures = 0
    next_dns_refresh = 0.0
    next_profile_refresh = 0.0

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    old_int = signal.signal(signal.SIGINT, stop)
    old_term = signal.signal(signal.SIGTERM, stop)
    try:
        while not stopping:
            present = tun_exists(config.vpn.tun_interface)
            guard.observe(present)
            state = nft.status()
            if not present and guard.failures >= config.failure_threshold and state == "VPN_ONLY":
                nft.apply("lock")
                print("TUN-интерфейс отсутствует; включена полная блокировка сети.", flush=True)
                state = "LOCKED"

            now = time.monotonic()
            if present and state == "VPN_ONLY" and now >= min(next_dns_refresh, next_profile_refresh):
                try:
                    if not servers or now >= next_profile_refresh:
                        servers = load_profile(config.vpn.source)
                        next_profile_refresh = now + config.profile_refresh_seconds
                    updated_endpoints = resolve_servers(servers)
                    if updated_endpoints != endpoints:
                        nft.apply("vpn", updated_endpoints, config.vpn.tun_interface)
                        endpoints = updated_endpoints
                        print(f"Список адресов серверов обновлён: {len(endpoints)}.", flush=True)
                    write_profile_cache(config.vpn.source, servers, endpoints, profile_cache_path())
                    refresh_failures = 0
                    next_dns_refresh = now + config.dns_refresh_seconds
                except (ProfileError, OSError, RuntimeError) as exc:
                    refresh_failures += 1
                    print(f"Не удалось обновить профиль или DNS ({refresh_failures}/{config.failure_threshold}): {exc}", flush=True)
                    next_dns_refresh = now + config.dns_refresh_seconds
                    next_profile_refresh = now + config.dns_refresh_seconds
                    if refresh_failures >= config.failure_threshold:
                        nft.apply("lock")
                        print("Повторные ошибки обновления профиля или DNS; включена полная блокировка.", flush=True)
            time.sleep(config.interval_seconds)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)
