"""Tests for app wiring: health endpoint, intel construction, startup/cleanup."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from pkggate.app import _build_intel, _health, build_app
from pkggate.config import Settings
from pkggate.intel.composite import CompositeIntel
from pkggate.intel.osv import OsvIntel


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "mirror_enabled": False,
        "live_fallback_enabled": False,
        "pypi_enabled": False,
        "audit_log": Path("/tmp/test-audit.log"),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _mock_proxy() -> MagicMock:
    p = MagicMock()
    p.startup = AsyncMock()
    p.shutdown = AsyncMock()
    p.register = MagicMock()
    return p


# ── health endpoint ───────────────────────────────────────────────────────────


class TestHealthEndpoint:
    async def test_returns_ok(self) -> None:
        app = web.Application()
        app.router.add_get("/-/pkggate/health", _health)
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/-/pkggate/health")
            assert resp.status == 200
            body = await resp.json()
            assert body == {"status": "ok"}

    async def test_content_type_is_json(self) -> None:
        app = web.Application()
        app.router.add_get("/-/pkggate/health", _health)
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/-/pkggate/health")
            assert "application/json" in resp.content_type


# ── _build_intel ──────────────────────────────────────────────────────────────


class TestBuildIntel:
    async def test_mirror_disabled_returns_osv_intel(self) -> None:
        s = _settings(mirror_enabled=False)
        intel = await _build_intel(s, fail_closed=True)
        assert isinstance(intel, OsvIntel)
        await intel.close()

    async def test_mirror_disabled_live_fallback_still_returns_osv(self) -> None:
        s = _settings(mirror_enabled=False, live_fallback_enabled=True)
        intel = await _build_intel(s, fail_closed=False)
        assert isinstance(intel, OsvIntel)
        await intel.close()

    async def test_mirror_enabled_returns_composite(self, tmp_path: Path) -> None:
        s = _settings(mirror_enabled=True, mirror_db=tmp_path / "m.db")
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            MockMirror.return_value = mock_mirror
            intel = await _build_intel(s, fail_closed=True)
        assert isinstance(intel, CompositeIntel)

    async def test_mirror_enabled_with_live_fallback_wires_live(self, tmp_path: Path) -> None:
        s = _settings(mirror_enabled=True, live_fallback_enabled=True, mirror_db=tmp_path / "m.db")
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            MockMirror.return_value = mock_mirror
            intel = await _build_intel(s, fail_closed=True)
        assert isinstance(intel, CompositeIntel)
        assert intel._live is not None

    async def test_mirror_enabled_without_live_fallback_has_no_live(self, tmp_path: Path) -> None:
        s = _settings(mirror_enabled=True, live_fallback_enabled=False, mirror_db=tmp_path / "m.db")
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            MockMirror.return_value = mock_mirror
            intel = await _build_intel(s, fail_closed=True)
        assert isinstance(intel, CompositeIntel)
        assert intel._live is None

    async def test_mirror_start_failure_falls_back_to_osv(self, tmp_path: Path) -> None:
        s = _settings(mirror_enabled=True, live_fallback_enabled=False, mirror_db=tmp_path / "m.db")
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            mock_mirror.start.side_effect = RuntimeError("network blocked")
            MockMirror.return_value = mock_mirror
            intel = await _build_intel(s, fail_closed=True)
        assert isinstance(intel, OsvIntel)
        mock_mirror.stop.assert_called_once()
        await intel.close()

    async def test_mirror_start_failure_calls_stop_before_fallback(self, tmp_path: Path) -> None:
        s = _settings(mirror_enabled=True, live_fallback_enabled=False, mirror_db=tmp_path / "m.db")
        stop_called_before_return = []
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            mock_mirror.start.side_effect = RuntimeError("disk full")
            mock_mirror.stop.side_effect = lambda: stop_called_before_return.append(True)
            MockMirror.return_value = mock_mirror
            intel = await _build_intel(s, fail_closed=True)
        assert stop_called_before_return == [True]
        await intel.close()

    async def test_mirror_start_failure_with_live_already_built_reuses_it(
        self, tmp_path: Path
    ) -> None:
        # live_fallback_enabled=True → live is built *before* mirror attempt,
        # so when mirror fails, we reuse the existing live instead of building a new one.
        s = _settings(mirror_enabled=True, live_fallback_enabled=True, mirror_db=tmp_path / "m.db")
        with patch("pkggate.app.OsvMirror") as MockMirror:
            mock_mirror = AsyncMock()
            mock_mirror.start.side_effect = RuntimeError("disk full")
            MockMirror.return_value = mock_mirror
            with patch("pkggate.app.OsvIntel") as MockOsvIntel:
                mock_live = MagicMock()
                MockOsvIntel.return_value = mock_live
                intel = await _build_intel(s, fail_closed=True)
        # OsvIntel should only be constructed once (for the live fallback), not again after failure
        assert MockOsvIntel.call_count == 1
        assert intel is mock_live


# ── build_app ─────────────────────────────────────────────────────────────────


class TestBuildApp:
    def test_app_has_required_keys(self) -> None:
        s = _settings()
        app = build_app(s)
        assert app["settings"] is s
        assert "policy" in app
        assert "audit" in app

    def test_health_route_registered(self) -> None:
        s = _settings()
        app = build_app(s)
        routes = [r.resource.canonical for r in app.router.routes()]
        assert "/-/pkggate/health" in routes

    def test_startup_and_cleanup_hooks_registered(self) -> None:
        s = _settings()
        app = build_app(s)
        # aiohttp may add its own internal hooks; verify ours are present
        assert len(app.on_startup) >= 1
        assert len(app.on_cleanup) >= 1


# ── startup / cleanup lifecycle ───────────────────────────────────────────────

_FAKE_INTEL = MagicMock()


class TestStartupLifecycle:
    async def test_npm_proxy_always_started(self) -> None:
        s = _settings(pypi_enabled=False)
        mock_npm = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))) as client:
                mock_npm.startup.assert_called_once()
                assert client.app.get("npm") is mock_npm

    async def test_pypi_proxy_started_when_enabled(self) -> None:
        s = _settings(pypi_enabled=True)
        mock_npm = _mock_proxy()
        mock_pypi = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app.PyPiProxy", return_value=mock_pypi),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))) as client:
                mock_pypi.startup.assert_called_once()
                mock_pypi.register.assert_called_once_with(client.app)
                assert client.app.get("pypi") is mock_pypi

    async def test_pypi_proxy_not_created_when_disabled(self) -> None:
        s = _settings(pypi_enabled=False)
        mock_npm = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app.PyPiProxy") as MockPyPi,
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))):
                MockPyPi.assert_not_called()

    async def test_health_endpoint_reachable_after_startup(self) -> None:
        s = _settings(pypi_enabled=False)
        mock_npm = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))) as client:
                resp = await client.get("/-/pkggate/health")
                assert resp.status == 200
                body = await resp.json()
                assert body == {"status": "ok"}


class TestCleanupLifecycle:
    async def test_npm_shutdown_called_on_cleanup(self) -> None:
        s = _settings(pypi_enabled=False)
        mock_npm = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))):
                pass
        mock_npm.shutdown.assert_called_once()

    async def test_pypi_shutdown_called_when_enabled(self) -> None:
        s = _settings(pypi_enabled=True)
        mock_npm = _mock_proxy()
        mock_pypi = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app.PyPiProxy", return_value=mock_pypi),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))):
                pass
        mock_pypi.shutdown.assert_called_once()
        mock_npm.shutdown.assert_called_once()

    async def test_cleanup_without_pypi_does_not_raise(self) -> None:
        s = _settings(pypi_enabled=False)
        mock_npm = _mock_proxy()
        with (
            patch("pkggate.app.NpmProxy", return_value=mock_npm),
            patch("pkggate.app._build_intel", new=AsyncMock(return_value=_FAKE_INTEL)),
        ):
            async with TestClient(TestServer(build_app(s))) as client:
                assert "pypi" not in client.app
            # no exception raised during cleanup
