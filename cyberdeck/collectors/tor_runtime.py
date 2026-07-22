from __future__ import annotations

import os
import shutil
import socket
from urllib.parse import urlparse

from cyberdeck.collectors.base import CollectionResult, Collector
from cyberdeck.schemas import SourceStatus


class TorRuntimeCollector(Collector):
    name = "Revision TOR autorizada"

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    async def collect(self) -> CollectionResult:
        if not self.enabled:
            return CollectionResult(
                SourceStatus(
                    name=self.name,
                    status="disabled",
                    records=0,
                    mode="real",
                    warning="Canal TOR no habilitado en el perfil organizacional; no se abren servicios .onion.",
                ),
                [],
            )
        proxy_url = os.getenv("TOR_SOCKS_PROXY_URL", "socks5h://tor-proxy:9050")
        proxy_status = _check_socks_proxy(proxy_url)
        if proxy_status:
            return CollectionResult(
                SourceStatus(
                    name=self.name,
                    status="configured",
                    records=0,
                    mode="real",
                    warning="Canal TOR disponible; usar solo con alcance autorizado, allowlist y sin descarga de payloads.",
                ),
                [],
            )
        tor_path = shutil.which("tor")
        if not tor_path:
            return CollectionResult(
                SourceStatus(
                    name=self.name,
                    status="missing",
                    records=0,
                    mode="real",
                    warning="Canal TOR no disponible; inicia el contenedor autorizado antes de habilitar busquedas .onion.",
                ),
                [],
            )
        return CollectionResult(SourceStatus(name=self.name, status="configured", records=0, mode="real", warning="Canal TOR disponible localmente; usar solo con alcance autorizado."), [])


def _check_socks_proxy(proxy_url: str) -> bool:
    parsed = urlparse(proxy_url)
    if parsed.scheme not in {"socks5", "socks5h"} or not parsed.hostname:
        return False
    port = parsed.port or 9050
    try:
        with socket.create_connection((parsed.hostname, port), timeout=2.5):
            return True
    except OSError:
        return False
