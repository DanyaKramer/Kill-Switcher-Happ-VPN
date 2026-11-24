"""High-level profile loading, caching, and firewall activation."""

from __future__ import annotations

from pathlib import Path

from .config import AppConfig, profile_cache_path
from .firewall import Nftables
from .profile import ProfileError, load_profile, read_profile_cache, resolve_servers, write_profile_cache


def get_profile(config: AppConfig, cache_path: Path | None = None):
    servers = load_profile(config.vpn.source)
    endpoints = resolve_servers(servers)
    write_profile_cache(config.vpn.source, servers, endpoints, cache_path or profile_cache_path())
    return servers, endpoints


def cached_profile(config: AppConfig, cache_path: Path | None = None):
    return read_profile_cache(config.vpn.source, cache_path or profile_cache_path())


def validate_profile(config: AppConfig, nft: Nftables, cache_path: Path | None = None):
    if nft.status() == "LOCKED":
        servers, endpoints = cached_profile(config, cache_path)
    else:
        servers, endpoints = get_profile(config, cache_path)
    nft.validate("vpn", endpoints, config.vpn.tun_interface)
    return servers, endpoints


def activate_vpn(config: AppConfig, nft: Nftables, cache_path: Path | None = None):
    if nft.status() == "LOCKED":
        # Do not open the network to refresh a subscription while locked.
        servers, endpoints = cached_profile(config, cache_path)
    else:
        servers, endpoints = get_profile(config, cache_path)
    nft.apply("vpn", endpoints, config.vpn.tun_interface)
    return servers, endpoints
