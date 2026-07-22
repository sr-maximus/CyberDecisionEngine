import asyncio

from cyberdeck.collectors import tor_runtime
from cyberdeck.collectors.tor_runtime import TorRuntimeCollector


def test_tor_runtime_disabled_does_not_probe_network():
    result = asyncio.run(TorRuntimeCollector(enabled=False).collect())

    assert result.status.status == "disabled"
    assert result.status.records == 0


def test_tor_runtime_uses_sidecar_proxy(monkeypatch):
    monkeypatch.setenv("TOR_SOCKS_PROXY_URL", "socks5h://tor-proxy:9050")
    monkeypatch.setattr(tor_runtime, "_check_socks_proxy", lambda value: value == "socks5h://tor-proxy:9050")

    result = asyncio.run(TorRuntimeCollector(enabled=True).collect())

    assert result.status.status == "configured"
    assert "Canal TOR disponible" in (result.status.warning or "")
