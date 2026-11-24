"""Parse local VLESS links and standard text subscriptions into firewall endpoints."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .firewall import Endpoint

MAX_PROFILE_BYTES = 2 * 1024 * 1024
CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
LINK_RE = re.compile(r"vless://[^\s\"'<>]+", re.IGNORECASE)


class ProfileError(ValueError):
    """Profile source could not be safely parsed or resolved."""


@dataclass(frozen=True)
class Server:
    host: str
    port: int
    protocol: str


def _transport(query: dict[str, list[str]]) -> str:
    network = (query.get("type") or query.get("network") or ["tcp"])[0].lower()
    if network in {"tcp", "raw", "domainsocket", "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "splithttp"}:
        return "tcp"
    if network in {"kcp", "quic"}:
        return "udp"
    raise ProfileError(f"Тип транспорта VLESS не поддерживается: {network}")


def parse_vless_link(link: str) -> Server:
    try:
        parsed = urlsplit(link.strip())
        if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.port:
            raise ProfileError("Некорректная ссылка VLESS: ожидается формат vless://UUID@ХОСТ:ПОРТ")
        if not parsed.username:
            raise ProfileError("В ссылке VLESS отсутствует идентификатор пользователя")
        host = parsed.hostname
        try:
            address = ipaddress.ip_address(host)
            if address.is_unspecified:
                raise ProfileError("В конфигурации указан неопределённый адрес сервера (0.0.0.0 или ::). Получите у провайдера рабочую конфигурацию VLESS.")
        except ProfileError:
            raise
        except ValueError:
            if any(ch.isspace() for ch in host) or "/" in host:
                raise ProfileError("Некорректное имя сервера VLESS")
        protocol = _transport(parse_qs(parsed.query))
        return Server(host, parsed.port, protocol)
    except ValueError as exc:
        if isinstance(exc, ProfileError):
            raise
        raise ProfileError("Некорректная ссылка VLESS или номер порта") from exc


def parse_subscription_text(text: str) -> tuple[Server, ...]:
    """Parse raw or base64-encoded newline-separated VLESS links."""
    text = text.lstrip("\ufeff").strip()
    if text.lower().startswith("happ://crypto"):
        raise ProfileError("Зашифрованную подписку Happ нельзя импортировать этим способом. Скопируйте JSON отдельного сервера в Happ.")
    links = LINK_RE.findall(text)
    if not links:
        compact = re.sub(r"\s+", "", text)
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True).decode("utf-8-sig")
        except (ValueError, UnicodeError) as exc:
            raise ProfileError("В источнике профиля не найдены читаемые ссылки VLESS") from exc
        links = LINK_RE.findall(decoded)
    if not links:
        raise ProfileError("В подписке нет ссылок VLESS. Ожидается обычный или Base64-список ссылок")
    servers: list[Server] = []
    for link in links:
        # Common text feeds place one URI per line; strip punctuation used as a delimiter.
        servers.append(parse_vless_link(link.rstrip(",;")))
    return tuple(dict.fromkeys(servers))


def _json_server(host: object, port: object, network: object = "tcp") -> Server:
    if not isinstance(host, str) or not host.strip():
        raise ProfileError("В исходящем соединении VLESS в JSON не указан адрес сервера")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ProfileError("В исходящем соединении VLESS в JSON указан некорректный порт")
    host = host.strip()
    if any(ch.isspace() or ch in "/\\@?#[]" for ch in host):
        raise ProfileError("В исходящем соединении VLESS в JSON указано некорректное имя сервера")
    transport = str(network or "tcp").lower()
    protocol = _transport({"type": [transport]})
    try:
        address = ipaddress.ip_address(host)
        if address.is_unspecified:
            raise ProfileError("JSON содержит неопределённый адрес сервера (0.0.0.0 или ::). Это нерабочий узел.")
    except ProfileError:
        raise
    except ValueError:
        if ":" in host:
            raise ProfileError("В исходящем соединении VLESS в JSON указан некорректный IP-адрес")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ProfileError("В исходящем соединении VLESS в JSON указано некорректное имя сервера") from exc
        labels = ascii_host.rstrip(".").split(".")
        if len(ascii_host) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ProfileError("В исходящем соединении VLESS в JSON указано некорректное имя сервера")
    return Server(host, port, protocol)


def parse_json_config(text: str) -> tuple[Server, ...]:
    """Extract VLESS server endpoints from common Xray and sing-box JSON shapes."""
    if len(text.encode("utf-8")) > MAX_PROFILE_BYTES:
        raise ProfileError("Размер JSON-конфигурации превышает ограничение 2 МиБ")
    try:
        root = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProfileError("Файл из редактора не является корректным JSON") from exc
    if not isinstance(root, dict):
        raise ProfileError("Ожидается JSON-объект с исходящим соединением VLESS")

    outbounds = root.get("outbounds")
    if isinstance(outbounds, list):
        objects = [item for item in outbounds if isinstance(item, dict)]
    elif str(root.get("protocol", root.get("type", ""))).lower() == "vless":
        objects = [root]
    else:
        objects = []

    servers: list[Server] = []
    for outbound in objects:
        protocol_name = str(outbound.get("protocol", outbound.get("type", ""))).lower()
        if protocol_name != "vless":
            continue
        stream_settings = outbound.get("streamSettings", {})
        if not isinstance(stream_settings, dict):
            stream_settings = {}
        transport_object = outbound.get("transport", {})
        if not isinstance(transport_object, dict):
            transport_object = {}
        network = stream_settings.get("network", transport_object.get("type", outbound.get("network", "tcp")))

        # Xray legacy outbound shape: settings.vnext[{address, port, users}].
        settings = outbound.get("settings", {})
        if not isinstance(settings, dict):
            settings = {}
        vnext = settings.get("vnext", [])
        if isinstance(vnext, list) and vnext:
            for node in vnext:
                if isinstance(node, dict):
                    servers.append(_json_server(node.get("address"), node.get("port"), network))
            continue

        # Xray current/simplified and sing-box shapes.
        host = outbound.get("server", settings.get("address", settings.get("server")))
        port = outbound.get("server_port", outbound.get("port", settings.get("port", settings.get("server_port"))))
        servers.append(_json_server(host, port, network))

    if not servers:
        raise ProfileError("В JSON не найден сервер VLESS. Скопируйте конфигурацию отдельного сервера из Happ.")
    return tuple(dict.fromkeys(servers))


def server_as_vless_source(server: Server) -> str:
    host = f"[{server.host}]" if ":" in server.host and not server.host.startswith("[") else server.host
    network = "kcp" if server.protocol == "udp" else "tcp"
    return f"vless://happ-killswitch-import@{host}:{server.port}?type={network}#ImportedFromHapp"


class _HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        if urlsplit(new_url).scheme.lower() != "https":
            raise ProfileError("Перенаправление подписки должно оставаться в HTTPS")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def load_profile(source: str, *, timeout: float = 10.0) -> tuple[Server, ...]:
    """Load a direct VLESS URI or fetch an HTTPS standard subscription."""
    if source.lower().startswith("vless://"):
        return (parse_vless_link(source),)
    parsed = urlsplit(source)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProfileError("Источник профиля должен быть ссылкой VLESS или адресом HTTPS-подписки")
    request = urllib.request.Request(source, headers={"User-Agent": "Happ-Kill-Switch/0.2"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTPSOnlyRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(MAX_PROFILE_BYTES + 1)
    except (OSError, urllib.error.URLError, ProfileError) as exc:
        raise ProfileError("Не удалось загрузить профиль по HTTPS") from exc
    if len(data) > MAX_PROFILE_BYTES:
        raise ProfileError("Ответ подписки превышает ограничение 2 МиБ")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return parse_subscription_text(text)


def resolve_servers(servers: tuple[Server, ...]) -> tuple[Endpoint, ...]:
    endpoints: set[Endpoint] = set()
    for server in servers:
        try:
            ipaddress.ip_address(server.host)
            addresses = (server.host,)
        except ValueError:
            try:
                sock_type = socket.SOCK_DGRAM if server.protocol == "udp" else socket.SOCK_STREAM
                records = socket.getaddrinfo(server.host, server.port, type=sock_type)
            except OSError as exc:
                raise ProfileError(f"Не удалось определить IP-адрес сервера VLESS ({type(exc).__name__})") from exc
            addresses = tuple(sorted({record[4][0] for record in records}))
        if any(ipaddress.ip_address(address).is_unspecified for address in addresses):
            raise ProfileError("Имя сервера VLESS разрешилось в неопределённый адрес. Получите у провайдера рабочую конфигурацию.")
        endpoints.update(Endpoint(address, server.port, server.protocol) for address in addresses)
    if not endpoints:
        raise ProfileError("Для профиля не удалось определить ни одного IP-адреса сервера")
    return tuple(sorted(endpoints, key=lambda endpoint: (endpoint.protocol, endpoint.port, endpoint.address)))


def source_fingerprint(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def write_profile_cache(source: str, servers: tuple[Server, ...], endpoints: tuple[Endpoint, ...], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = {
        "source_hash": source_fingerprint(source),
        "updated_at": int(time.time()),
        "servers": [{"host": item.host, "port": item.port, "protocol": item.protocol} for item in servers],
        "endpoints": [{"address": item.address, "port": item.port, "protocol": item.protocol} for item in endpoints],
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(content), encoding="utf-8")
    temporary.replace(path)


def read_profile_cache(source: str, path: Path, *, now: int | None = None) -> tuple[tuple[Server, ...], tuple[Endpoint, ...]]:
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
        if content.get("source_hash") != source_fingerprint(source):
            raise ProfileError("Кэш относится к другой конфигурации. Обновите профиль при доступной сети.")
        current = int(time.time()) if now is None else now
        if current - int(content["updated_at"]) > CACHE_MAX_AGE_SECONDS:
            raise ProfileError("Кэш профиля старше 24 часов. Обновите профиль при доступной сети.")
        servers = tuple(Server(item["host"], int(item["port"]), item["protocol"]) for item in content["servers"])
        endpoints = tuple(Endpoint(item["address"], int(item["port"]), item["protocol"]) for item in content["endpoints"])
        if not servers or not endpoints:
            raise ProfileError("Кэш профиля пуст. Обновите профиль при доступной сети.")
        return servers, endpoints
    except ProfileError:
        raise
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProfileError("Нет действительного кэша профиля. Сначала запустите check при доступной сети.") from exc
