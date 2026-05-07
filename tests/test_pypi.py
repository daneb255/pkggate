"""PyPI proxy: simple-index filtering, file gate, integrity verification."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from pkggate.audit import AuditLogger
from pkggate.intel import CLEAN, Verdict
from pkggate.policy.engine import Policy, PolicyEngine
from pkggate.proxy.pypi import (
    PyPiProxy,
    _parse_file_identity,
    _version_from_filename,
)


class _StubIntel:
    """Routes verdicts by (project, version)."""

    def __init__(self, malicious: dict[tuple[str, str], Verdict] | None = None) -> None:
        self.malicious = malicious or {}
        self.calls: list[tuple[str, str, str]] = []

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        self.calls.append((ecosystem, name, version))
        return self.malicious.get((name, version), CLEAN)

    async def close(self) -> None:
        pass


class _UpstreamHarness:
    """Stand-in for pypi.org/simple and files.pythonhosted.org."""

    def __init__(self) -> None:
        self.simple_docs: dict[str, dict] = {}
        self.files: dict[str, bytes] = {}
        self.simple_calls: list[str] = []
        self.file_calls: list[str] = []

    def make_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/simple/{project}/", self._simple)
        app.router.add_get("/packages/{path:.*}", self._file)
        return app

    async def _simple(self, request: web.Request) -> web.Response:
        project = request.match_info["project"]
        self.simple_calls.append(project)
        doc = self.simple_docs.get(project)
        if doc is None:
            return web.Response(status=404)
        return web.json_response(doc)

    async def _file(self, request: web.Request) -> web.Response:
        # Routes register `/packages/{path:.*}`; harness keys files under the
        # full path (`packages/...`) for readability so the mapping mirrors
        # files.pythonhosted.org.
        path = "packages/" + request.match_info["path"]
        self.file_calls.append(path)
        body = self.files.get(path)
        if body is None:
            return web.Response(status=404)
        return web.Response(status=200, body=body)


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
    base = str(upstream_server.make_url("/"))
    proxy = PyPiProxy(
        upstream_simple=base + "simple/",
        upstream_files=base,
        intel=intel,
        policy=policy_engine,
        audit=audit,
        public_base_url="http://proxy.local",
        verify_integrity=True,
    )
    await proxy.startup()
    proxy_app = web.Application()
    proxy.register(proxy_app)
    proxy_app.on_cleanup.append(lambda _: proxy.shutdown())
    proxy_app.on_cleanup.append(lambda _: upstream_server.close())
    client = TestClient(TestServer(proxy_app))
    await client.start_server()
    return client, upstream


class TestFilenameParsing:
    @pytest.mark.parametrize(
        "filename,project,version",
        [
            ("requests-2.31.0-py3-none-any.whl", "requests", "2.31.0"),
            ("Django-4.2.7.tar.gz", "django", "4.2.7"),
            ("numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl", "numpy", "1.26.0"),
        ],
    )
    def test_parse_known_forms(self, filename: str, project: str, version: str) -> None:
        name, ver = _parse_file_identity(filename)
        assert name is not None
        from packaging.utils import canonicalize_name

        assert canonicalize_name(name) == project
        assert ver == version

    def test_unparseable_returns_none(self) -> None:
        assert _parse_file_identity("garbage.bin") == (None, None)

    def test_version_from_filename_rejects_wrong_project(self) -> None:
        assert _version_from_filename("django", "requests-2.31.0-py3-none-any.whl") is None


class TestSimpleIndex:
    async def test_filters_malicious_versions(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("requests", "2.31.0"): Verdict(
                    malicious=True,
                    reason="osv_malicious_advisory",
                    advisory_id="MAL-PYPI-1",
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.simple_docs["requests"] = {
                "meta": {"api-version": "1.0"},
                "name": "requests",
                "files": [
                    {
                        "filename": "requests-2.30.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.30.0-py3-none-any.whl",
                        "hashes": {"sha256": "a" * 64},
                    },
                    {
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/cc/dd/requests-2.31.0-py3-none-any.whl",
                        "hashes": {"sha256": "b" * 64},
                    },
                ],
            }
            resp = await client.get("/simple/Requests/")  # exercise canonicalize_name
            assert resp.status == 200
            doc = await resp.json()
            files = doc["files"]
            assert len(files) == 1
            assert files[0]["filename"] == "requests-2.30.0-py3-none-any.whl"
            # URL must be rewritten through the proxy so the file gate fires.
            assert files[0]["url"].startswith("http://proxy.local/packages/")
        finally:
            await client.close()

    async def test_simple_404_is_passed_through(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        client, _ = await _build(_StubIntel(), policy_engine, audit)
        try:
            resp = await client.get("/simple/does-not-exist/")
            assert resp.status == 404
        finally:
            await client.close()


class TestFileGate:
    async def test_blocks_malicious_on_direct_file_request(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel(
            malicious={
                ("requests", "2.31.0"): Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-X"
                )
            }
        )
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.files["packages/cc/dd/requests-2.31.0-py3-none-any.whl"] = b"payload"
            resp = await client.get("/packages/cc/dd/requests-2.31.0-py3-none-any.whl")
            assert resp.status == 403
            body = await resp.json()
            assert body["rule"] == "block_malicious"
            assert upstream.file_calls == []  # never even fetched upstream
        finally:
            await client.close()

    async def test_serves_file_when_clean_and_hash_matches(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        payload = b"this is a wheel"
        sha = hashlib.sha256(payload).hexdigest()
        intel = _StubIntel()
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.simple_docs["requests"] = {
                "files": [
                    {
                        "filename": "requests-2.30.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.30.0-py3-none-any.whl",
                        "hashes": {"sha256": sha},
                    }
                ]
            }
            upstream.files["packages/aa/bb/requests-2.30.0-py3-none-any.whl"] = payload

            # Browse the index first to prime the hash cache.
            await client.get("/simple/requests/")
            resp = await client.get("/packages/aa/bb/requests-2.30.0-py3-none-any.whl")
            assert resp.status == 200
            assert await resp.read() == payload
        finally:
            await client.close()

    async def test_rejects_on_hash_mismatch(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        intel = _StubIntel()
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            wrong_sha = "0" * 64  # claim doesn't match the actual bytes
            upstream.simple_docs["requests"] = {
                "files": [
                    {
                        "filename": "requests-2.30.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.30.0-py3-none-any.whl",
                        "hashes": {"sha256": wrong_sha},
                    }
                ]
            }
            upstream.files["packages/aa/bb/requests-2.30.0-py3-none-any.whl"] = b"tampered"

            await client.get("/simple/requests/")
            resp = await client.get("/packages/aa/bb/requests-2.30.0-py3-none-any.whl")
            assert resp.status == 502
            body = await resp.json()
            assert body["rule"] == "integrity_mismatch"
        finally:
            await client.close()

    async def test_lockfile_direct_hit_prefetches_hash(
        self, policy_engine: PolicyEngine, audit: AuditLogger
    ) -> None:
        # Simulates pip resolving from a lockfile: it never browses the
        # simple index, so the proxy must fetch it on demand to learn the
        # expected hash.
        payload = b"sdist contents"
        sha = hashlib.sha256(payload).hexdigest()
        intel = _StubIntel()
        client, upstream = await _build(intel, policy_engine, audit)
        try:
            upstream.simple_docs["django"] = {
                "files": [
                    {
                        "filename": "Django-4.2.7.tar.gz",
                        "url": "https://files.pythonhosted.org/packages/ee/ff/Django-4.2.7.tar.gz",
                        "hashes": {"sha256": sha},
                    }
                ]
            }
            upstream.files["packages/ee/ff/Django-4.2.7.tar.gz"] = payload

            resp = await client.get("/packages/ee/ff/Django-4.2.7.tar.gz")
            assert resp.status == 200
            assert await resp.read() == payload
            # Index was fetched on demand to fill the hash cache.
            assert upstream.simple_calls == ["django"]
        finally:
            await client.close()
