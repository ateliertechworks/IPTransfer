"""LAN peer discovery via mDNS/DNS-SD (zeroconf).

Each node advertises one ``_up2p-sync._tcp.local.`` service whose TXT record
carries the application ID, device ID and supported protocol versions.
Browsers ignore services with a different ``app`` value, so unrelated
applications using the same SDK never see or dial each other.

Discovery results are *hints only*: advertised IDs and addresses are
unauthenticated. Identity and authorization are established by the
connection handshake (cryptographically from Milestone 2 onward).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

import ifaddr
from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from .transport import SUPPORTED_VERSIONS

log = logging.getLogger(__name__)

SERVICE_TYPE = "_up2p-sync._tcp.local."
RESOLVE_TIMEOUT_MS = 3000


@dataclass(frozen=True)
class DiscoveredPeer:
    device_id: str
    device_name: str
    app_id: str
    addresses: tuple[str, ...]
    port: int
    versions: tuple[int, ...]


def local_ipv4_addresses() -> list[str]:
    """Non-loopback, non-link-local IPv4 addresses of this host."""
    found: set[str] = set()
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if ip.is_IPv4 and isinstance(ip.ip, str):
                if not ip.ip.startswith(("127.", "169.254.")):
                    found.add(ip.ip)
    return sorted(found)


def _decode_properties(raw: dict[bytes, bytes | None]) -> dict[str, str]:
    props: dict[str, str] = {}
    for key, value in raw.items():
        try:
            props[key.decode("utf-8")] = value.decode("utf-8") if value is not None else ""
        except UnicodeDecodeError:
            continue
    return props


def _parse_versions(raw: str) -> tuple[int, ...]:
    versions = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            versions.append(int(part))
    return tuple(versions)


class PeerDiscovery:
    def __init__(
        self,
        *,
        app_id: str,
        device_id: str,
        device_name: str,
        port: int,
        addresses: Iterable[str],
        on_discovered: Callable[[DiscoveredPeer], Awaitable[None]],
        on_lost: Callable[[str], Awaitable[None]],
    ) -> None:
        self._app_id = app_id
        self._device_id = device_id
        self._device_name = device_name
        self._port = port
        self._addresses = list(addresses)
        self._on_discovered = on_discovered
        self._on_lost = on_lost
        self._azc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._info: AsyncServiceInfo | None = None
        self._names: dict[str, str] = {}  # service name -> device id
        self._peers: dict[str, DiscoveredPeer] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def peers(self) -> dict[str, DiscoveredPeer]:
        return dict(self._peers)

    async def start(self) -> None:
        self._azc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        instance = f"up2p-{self._app_id[:20]}-{self._device_id[:24]}"
        self._info = AsyncServiceInfo(
            SERVICE_TYPE,
            f"{instance}.{SERVICE_TYPE}",
            port=self._port,
            parsed_addresses=self._addresses,
            server=f"{instance}.local.",
            properties={
                "app": self._app_id,
                "dev": self._device_id,
                "name": self._device_name[:200],
                "pv": ",".join(str(v) for v in SUPPORTED_VERSIONS),
            },
        )
        try:
            # zeroconf returns a task that completes once probing/announcing is done.
            registration = await self._azc.async_register_service(
                self._info, allow_name_change=True
            )
            await registration
            self._browser = AsyncServiceBrowser(
                self._azc.zeroconf, [SERVICE_TYPE], handlers=[self._on_state_change]
            )
        except BaseException:
            await self._azc.async_close()
            self._azc = None
            raise
        log.info("mDNS: advertising %s on %s:%d", instance, self._addresses, self._port)

    async def stop(self) -> None:
        if self._azc is None:
            return
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._browser is not None:
            await self._browser.async_cancel()
        if self._info is not None:
            try:
                # Await the returned task so goodbye packets are sent before closing.
                await (await self._azc.async_unregister_service(self._info))
            except Exception:
                log.debug("mDNS unregister failed", exc_info=True)
        await self._azc.async_close()
        self._azc = None
        self._browser = None
        self._names.clear()
        self._peers.clear()

    def _on_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change is ServiceStateChange.Removed:
            coro = self._handle_removed(name)
        else:
            coro = self._resolve(service_type, name)
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resolve(self, service_type: str, name: str) -> None:
        if self._azc is None:
            return
        info = AsyncServiceInfo(service_type, name)
        try:
            if not await info.async_request(self._azc.zeroconf, RESOLVE_TIMEOUT_MS):
                return
        except Exception:
            log.debug("mDNS resolve failed for %s", name, exc_info=True)
            return
        props = _decode_properties(info.properties or {})
        if props.get("app") != self._app_id:
            return  # a different application using the same SDK
        device_id = props.get("dev", "")
        if not device_id or device_id == self._device_id or info.port is None:
            return
        peer = DiscoveredPeer(
            device_id=device_id,
            device_name=props.get("name", ""),
            app_id=self._app_id,
            addresses=tuple(info.parsed_addresses(IPVersion.V4Only)),
            port=info.port,
            versions=_parse_versions(props.get("pv", "")),
        )
        if not peer.addresses:
            return
        previous = self._peers.get(device_id)
        self._names[name] = device_id
        self._peers[device_id] = peer
        if previous != peer:
            log.info("mDNS: discovered %s at %s:%d", device_id, peer.addresses, peer.port)
            await self._on_discovered(peer)

    async def _handle_removed(self, name: str) -> None:
        device_id = self._names.pop(name, None)
        if device_id is None:
            return
        self._peers.pop(device_id, None)
        log.info("mDNS: lost %s", device_id)
        await self._on_lost(device_id)
