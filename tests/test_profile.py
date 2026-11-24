import base64
import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from happ_killswitch.profile import (
    ProfileError,
    Server,
    parse_subscription_text,
    parse_json_config,
    parse_vless_link,
    read_profile_cache,
    resolve_servers,
    write_profile_cache,
)
from happ_killswitch.firewall import Endpoint


def test_parse_vless_link_with_hostname_and_tcp_transport():
    server = parse_vless_link("vless://uuid@example.net:443?type=ws&security=tls#Node")
    assert server == Server("example.net", 443, "tcp")


def test_parse_vless_link_maps_kcp_to_udp():
    server = parse_vless_link("vless://uuid@192.0.2.10:2087?type=kcp")
    assert server == Server("192.0.2.10", 2087, "udp")


@pytest.mark.parametrize("link", ["vmess://uuid@host:443", "vless://host:443", "vless://uuid@host:notaport"])
def test_invalid_vless_link_is_rejected(link):
    with pytest.raises(ProfileError):
        parse_vless_link(link)


def test_unspecified_server_placeholder_is_rejected():
    with pytest.raises(ProfileError, match="неопределённый адрес"):
        parse_vless_link("vless://uuid@0.0.0.0:1?type=tcp")


def test_parse_xray_json_vless_outbound():
    config = json.dumps({
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "node.example", "port": 443, "users": [{"id": "secret"}]}]},
            "streamSettings": {"network": "ws"},
        }]
    })
    assert parse_json_config(config) == (Server("node.example", 443, "tcp"),)


def test_parse_sing_box_json_vless_outbound_and_udp_transport():
    config = json.dumps({"outbounds": [{"type": "vless", "server": "192.0.2.5", "server_port": 2053, "transport": {"type": "quic"}}]})
    assert parse_json_config(config) == (Server("192.0.2.5", 2053, "udp"),)


def test_parse_multiple_vless_servers_but_ignore_direct_outbound():
    config = json.dumps({"outbounds": [
        {"protocol": "freedom"},
        {"protocol": "vless", "settings": {"vnext": [{"address": "one.example", "port": 443}]}},
        {"protocol": "vless", "settings": {"address": "two.example", "port": 8443}},
    ]})
    assert parse_json_config(config) == (
        Server("one.example", 443, "tcp"),
        Server("two.example", 8443, "tcp"),
    )


def test_json_placeholder_and_unknown_shape_are_rejected():
    with pytest.raises(ProfileError, match="неопределённый"):
        parse_json_config(json.dumps({"type": "vless", "server": "0.0.0.0", "server_port": 1}))
    with pytest.raises(ProfileError, match="не найден сервер VLESS"):
        parse_json_config(json.dumps({"outbounds": [{"protocol": "freedom"}]}))


def test_parse_plain_and_base64_subscription_lists_and_deduplicates():
    body = "vless://uuid@one.example:443?type=tcp\nvless://uuid@two.example:2053?type=grpc\n"
    expected = (Server("one.example", 443, "tcp"), Server("two.example", 2053, "tcp"))
    assert parse_subscription_text(body + body) == expected
    encoded = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
    assert parse_subscription_text(encoded) == expected


def test_encrypted_happ_subscription_has_actionable_error():
    with pytest.raises(ProfileError, match="Зашифрованную подписку Happ"):
        parse_subscription_text("happ://cryptoABCDEF")


def test_resolve_servers_expands_all_addresses(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.4", 443)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::4", 443, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    assert resolve_servers((Server("node.example", 443, "tcp"),)) == (
        Endpoint("198.51.100.4", 443, "tcp"),
        Endpoint("2001:db8::4", 443, "tcp"),
    )


def test_cache_contains_endpoint_metadata_but_not_vless_credentials(tmp_path: Path):
    source = "vless://private-uuid@node.example:443?type=tcp"
    servers = (Server("node.example", 443, "tcp"),)
    endpoints = (Endpoint("198.51.100.4", 443, "tcp"),)
    cache = tmp_path / "profile.json"
    write_profile_cache(source, servers, endpoints, cache)
    assert "private-uuid" not in cache.read_text(encoding="utf-8")
    assert read_profile_cache(source, cache)[1] == endpoints


def test_cache_rejects_different_source_and_expired_data(tmp_path: Path):
    cache = tmp_path / "profile.json"
    servers = (Server("node.example", 443, "tcp"),)
    endpoints = (Endpoint("198.51.100.4", 443, "tcp"),)
    write_profile_cache("vless://id@one.example:443", servers, endpoints, cache)
    with pytest.raises(ProfileError, match="другой конфигурации"):
        read_profile_cache("vless://id@two.example:443", cache)
    with pytest.raises(ProfileError, match="старше 24 часов"):
        read_profile_cache("vless://id@one.example:443", cache, now=2**31)
