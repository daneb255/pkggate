"""npm proxy: metadata filtering, tarball gate, pass-through."""

from __future__ import annotations

from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from pkggate.audit import AuditLogger
from pkggate.intel import CLEAN, Verdict
from pkggate.policy.engine import Policy, PolicyEngine
from pkggate.proxy.npm import NpmProxy


class _StubIntel:
    def __init__(self, malicious: dict[tuple[str, str], Verdict] | None = None) -> None:
        self.malicious = malicious or {}
        self.calls: list[tuple[str, str, str]] = []

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        self.calls.append((ecosystem, name, version))
        return self.malicious.get((name, version), CLEAN)

    async def close(self) -> None:
        pass


class _UpstreamHarness:
    """Minimal npm registry stand-in."""

    def __init__(self) -> None:
        self.packages: dict[str, dict] = {}
        self.tarballs: dict[str, bytes] = {}
        self.calls: list[str] = []

    def make_app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("GET", "/{path:.*}", self._handler)
        return app

    async def _handler(self, request: web.Request) -> web.Response:
        path = request.match_info["path"]
        self.calls.append(path)
        if "/-/" in path:
            body = self.tarballs.get(path)
            if body is None:
                return web.Response(status=404)
            return web.Response(status=200, body=body, content_type="application/octet-stream")
        doc = self.packages.get(path.rstrip("/"))
        if doc is None:
            return web.Response(status=404, body=b"Not found", content_type="application/json")
        return web.json_response(doc)


@pytest.fixture
def policy_engine() -> PolicyEngine:
    return PolicyEngine(Policy(block_malicious=True))


@pytest.fixture
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.log")


async def _build(
    intel: _StubIntel,
    policy_engine: PolicyEngine,
    audit: AuditLogger,
) -> tuple[TestClient, _UpstreamHarness]:
    upstream = _UpstreamHarness()
    upstream_server = TestServer(upstream.make_app())
    await upstream_server.start_server()
    base = str(upstream_server.make_url("/")).rstrip("/")
    proxy = NpmProxy(upstream=base, intel=intel, policy=policy_engine, audit=audit)
    await proxy.startup()
    proxy_app = web.Application()
    proxy_app.router.add_route("*", "/{path:.*}", proxy.handle)
    proxy_app.on_cleanup.append(lambda _: proxy.shutdown())
    proxy_app.on_cleanup.append(lambda _: upstream_server.close())
    client = TestClient(TestServer(proxy_app))
    await client.start_server()
    return client, upstream


class TestMetadataFiltering:
    async def test_filters_malicious_version(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("lodash", "4.17.20"): Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-1"
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.packages["lodash"] = {
                "name": "lodash",
                "versions": {
                    "4.17.20": {"name": "lodash", "version": "4.17.20"},
                    "4.17.21": {"name": "lodash", "version": "4.17.21"},
                },
                "time": {
                    "4.17.20": "2021-01-01T00:00:00Z",
                    "4.17.21": "2021-06-01T00:00:00Z",
                },
                "dist-tags": {"latest": "4.17.21"},
            }
            resp = await client.get("/lodash")
            assert resp.status == 200
            doc = await resp.json()
            assert "4.17.20" not in doc["versions"]
            assert "4.17.21" in doc["versions"]
            assert "4.17.20" not in doc["time"]
            assert doc["dist-tags"]["latest"] == "4.17.21"
            assert resp.headers.get("x-pkggate-blocked-versions") == "1"
        finally:
            await client.close()

    async def test_latest_tag_updated_when_blocked(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("pkg", "2.0.0"): Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-2"
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.packages["pkg"] = {
                "name": "pkg",
                "versions": {"1.0.0": {}, "2.0.0": {}},
                "time": {},
                "dist-tags": {"latest": "2.0.0"},
            }
            resp = await client.get("/pkg")
            assert resp.status == 200
            doc = await resp.json()
            assert "2.0.0" not in doc["versions"]
            assert doc["dist-tags"].get("latest") == "1.0.0"
        finally:
            await client.close()

    async def test_all_versions_clean_passes_through(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        client, upstream = await _build(_StubIntel(), policy_engine, audit)
        try:
            upstream.packages["lodash"] = {
                "name": "lodash",
                "versions": {"4.17.21": {}},
                "time": {},
                "dist-tags": {"latest": "4.17.21"},
            }
            resp = await client.get("/lodash")
            assert resp.status == 200
            doc = await resp.json()
            assert "4.17.21" in doc["versions"]
            assert resp.headers.get("x-pkggate-blocked-versions") == "0"
        finally:
            await client.close()

    async def test_metadata_404_passed_through(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        client, _ = await _build(_StubIntel(), policy_engine, audit)
        try:
            resp = await client.get("/does-not-exist")
            assert resp.status == 404
        finally:
            await client.close()


class TestTarballGate:
    async def test_blocks_malicious_before_upstream_fetch(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("evil-pkg", "1.0.0"): Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-3"
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.tarballs["evil-pkg/-/evil-pkg-1.0.0.tgz"] = b"bad payload"
            resp = await client.get("/evil-pkg/-/evil-pkg-1.0.0.tgz")
            assert resp.status == 403
            body = await resp.json()
            assert body["rule"] == "block_malicious"
            assert body["package"] == "evil-pkg"
            assert upstream.calls == []
        finally:
            await client.close()

    async def test_serves_clean_tarball(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        payload = b"valid tarball contents"
        client, upstream = await _build(_StubIntel(), policy_engine, audit)
        try:
            upstream.tarballs["lodash/-/lodash-4.17.21.tgz"] = payload
            resp = await client.get("/lodash/-/lodash-4.17.21.tgz")
            assert resp.status == 200
            assert await resp.read() == payload
        finally:
            await client.close()

    async def test_scoped_package_tarball_blocked(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("@aws-sdk/client-s3", "3.0.0"): Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-4"
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.tarballs["@aws-sdk/client-s3/-/client-s3-3.0.0.tgz"] = b"payload"
            resp = await client.get("/@aws-sdk/client-s3/-/client-s3-3.0.0.tgz")
            assert resp.status == 403
            assert upstream.calls == []
        finally:
            await client.close()

    async def test_scoped_package_tarball_served_when_clean(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        payload = b"scoped package bytes"
        client, upstream = await _build(_StubIntel(), policy_engine, audit)
        try:
            upstream.tarballs["@scope/lib/-/lib-1.2.3.tgz"] = payload
            resp = await client.get("/@scope/lib/-/lib-1.2.3.tgz")
            assert resp.status == 200
            assert await resp.read() == payload
        finally:
            await client.close()


class TestPassThrough:
    async def test_non_package_path_forwarded(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        client, upstream = await _build(_StubIntel(), policy_engine, audit)
        try:
            resp = await client.get("/-/ping")
            assert resp.status == 404
            assert upstream.calls == ["-/ping"]
        finally:
            await client.close()
