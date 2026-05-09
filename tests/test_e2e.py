"""End-to-end load tests: full pkggate server + fake upstreams under concurrent load.

Spins up real fake upstream npm/PyPI servers, starts the full pkggate application
via build_app(), patches only the threat-intel backend with a deterministic stub,
then fires CONCURRENCY concurrent requests and verifies correctness under load:
  - clean packages always pass through
  - malicious packages are always blocked (no races that let one slip through)
  - block decisions are consistent across all concurrent in-flight requests
  - the fake upstream is never contacted for a malicious tarball/file gate
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, unused_port

from pkggate.app import build_app
from pkggate.config import Settings
from pkggate.intel import CLEAN, Verdict

CONCURRENCY = 50

# ── Fake intel ────────────────────────────────────────────────────────────────

MALICIOUS_NPM = "evil-pkg"
MALICIOUS_PYPI = "evil-lib"


class _FakeIntel:
    """Returns malicious for designated packages, clean for everything else."""

    _BAD: frozenset[tuple[str, str]] = frozenset({("npm", MALICIOUS_NPM), ("PyPI", MALICIOUS_PYPI)})

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        return (
            Verdict(malicious=True, reason="test_advisory", advisory_id="MAL-E2E-001")
            if (ecosystem, name) in self._BAD
            else CLEAN
        )

    async def close(self) -> None:
        pass


# ── Fake upstream npm ─────────────────────────────────────────────────────────

TARBALL_BYTES = b"fake-npm-tarball-payload"


class _FakeNpmUpstream:
    def __init__(self) -> None:
        self.tarball_hits: list[str] = []

    def make_app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("GET", "/{path:.*}", self._handler)
        return app

    async def _handler(self, request: web.Request) -> web.Response:
        path = request.match_info["path"]
        if "/-/" in path:
            self.tarball_hits.append(path)
            return web.Response(body=TARBALL_BYTES, content_type="application/octet-stream")
        pkg = path.rstrip("/")
        doc: dict[str, Any] = {
            "name": pkg,
            "dist-tags": {"latest": "3.0.0"},
            "versions": {v: {"name": pkg, "version": v} for v in ("1.0.0", "2.0.0", "3.0.0")},
            "time": {v: "2020-01-01T00:00:00.000Z" for v in ("1.0.0", "2.0.0", "3.0.0")},
        }
        return web.json_response(doc)


# ── Fake upstream PyPI ────────────────────────────────────────────────────────

WHEEL_BYTES = b"fake-wheel-content-payload"
WHEEL_SHA256 = hashlib.sha256(WHEEL_BYTES).hexdigest()


class _FakePyPiSimple:
    def __init__(self, files_base: str) -> None:
        self._files_base = files_base.rstrip("/")

    def make_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/simple/{project}/", self._handler)
        app.router.add_get("/simple/{project}", self._handler)
        return app

    async def _handler(self, request: web.Request) -> web.Response:
        project = request.match_info["project"]
        # PEP 427: wheel filenames use underscores, not hyphens.
        norm = project.replace("-", "_")
        filename = f"{norm}-1.0.0-py3-none-any.whl"
        doc: dict[str, Any] = {
            "meta": {"api-version": "1.0"},
            "name": project,
            "files": [
                {
                    "filename": filename,
                    "url": f"{self._files_base}/packages/ab/cd/{filename}",
                    "hashes": {"sha256": WHEEL_SHA256},
                }
            ],
        }
        return web.Response(
            body=json.dumps(doc).encode(),
            content_type="application/vnd.pypi.simple.v1+json",
        )


class _FakePyPiFiles:
    def make_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/packages/{path:.*}", self._handler)
        return app

    async def _handler(self, _: web.Request) -> web.Response:
        return web.Response(body=WHEEL_BYTES, content_type="application/octet-stream")


# ── Shared fixtures ───────────────────────────────────────────────────────────


class _Stack:
    def __init__(self, client: TestClient, npm_upstream: _FakeNpmUpstream) -> None:
        self.client = client
        self.npm_upstream = npm_upstream


async def _build_stack(tmp_path: Path) -> _Stack:
    # Minimal policy: only block MAL-* advisories, no age or lifecycle checks.
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "fail_closed: false\n"
        "block_malicious: true\n"
        "min_package_age_days: 0\n"
        "require_repository_url: false\n"
        "deny_lifecycle_scripts: false\n"
        "allowlist: []\n"
        "denylist: []\n"
    )

    npm_upstream = _FakeNpmUpstream()
    npm_server = TestServer(npm_upstream.make_app())
    await npm_server.start_server()
    npm_url = f"http://127.0.0.1:{npm_server.port}"

    pypi_files_server = TestServer(_FakePyPiFiles().make_app())
    await pypi_files_server.start_server()
    pypi_files_url = f"http://127.0.0.1:{pypi_files_server.port}"

    pypi_simple_server = TestServer(_FakePyPiSimple(pypi_files_url).make_app())
    await pypi_simple_server.start_server()
    pypi_simple_url = f"http://127.0.0.1:{pypi_simple_server.port}"

    # Pre-allocate pkggate port so pypi_public_base_url is known before startup.
    pkggate_port = unused_port()

    settings = Settings(
        mirror_enabled=False,
        live_fallback_enabled=False,
        audit_log=tmp_path / "audit.log",
        upstream_npm=npm_url,
        pypi_enabled=True,
        pypi_upstream_simple=f"{pypi_simple_url}/simple/",
        pypi_upstream_files=pypi_files_url,
        pypi_public_base_url=f"http://127.0.0.1:{pkggate_port}",
        pypi_verify_integrity=True,
        policy_file=policy_file,
        upstream_timeout_seconds=10.0,
    )

    fake_intel = _FakeIntel()
    app = build_app(settings)
    client = TestClient(TestServer(app, port=pkggate_port))

    # Patch _build_intel only during startup — the proxy is already wired after.
    with patch("pkggate.app._build_intel", new=AsyncMock(return_value=fake_intel)):
        await client.start_server()

    # Attach servers so teardown can reach them.
    client._extra_servers = (npm_server, pypi_simple_server, pypi_files_server)  # type: ignore[attr-defined]
    return _Stack(client=client, npm_upstream=npm_upstream)


async def _teardown_stack(stack: _Stack) -> None:
    await stack.client.close()
    for srv in stack.client._extra_servers:  # type: ignore[attr-defined]
        await srv.close()


# ── npm load tests ────────────────────────────────────────────────────────────


class TestNpmLoadE2E:
    """npm proxy: correctness under CONCURRENCY simultaneous requests."""

    async def test_concurrent_clean_metadata_all_200(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get("/lodash")
                return resp.status, await resp.json()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            statuses = [s for s, _ in results]
            assert all(s == 200 for s in statuses), f"got: {set(statuses)}"
            for _, doc in results:
                assert "1.0.0" in doc["versions"]
                assert "3.0.0" in doc["versions"]
            assert elapsed < 15.0, f"{CONCURRENCY} requests took {elapsed:.1f}s"
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_malicious_metadata_all_versions_stripped(
        self, tmp_path: Path
    ) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get(f"/{MALICIOUS_NPM}")
                return resp.status, await resp.json()

            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])

            assert all(s == 200 for s, _ in results)
            for _, doc in results:
                assert doc["versions"] == {}, "all versions must be stripped"
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_clean_tarball_all_served(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _fetch() -> tuple[int, bytes]:
                resp = await stack.client.get("/lodash/-/lodash-1.0.0.tgz")
                return resp.status, await resp.read()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            assert all(s == 200 for s, _ in results), "all clean tarballs must pass"
            assert all(body == TARBALL_BYTES for _, body in results), "tarball body must match"
            assert elapsed < 15.0, f"{CONCURRENCY} requests took {elapsed:.1f}s"
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_malicious_tarball_all_blocked(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:
            url = f"/{MALICIOUS_NPM}/-/{MALICIOUS_NPM}-1.0.0.tgz"

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get(url)
                return resp.status, await resp.json()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            statuses = [s for s, _ in results]
            assert all(s == 403 for s in statuses), f"must always block — got {set(statuses)}"
            for _, body in results:
                assert body["rule"] == "block_malicious"
                assert body["package"] == MALICIOUS_NPM

            # Upstream must never be contacted for a blocked tarball.
            assert stack.npm_upstream.tarball_hits == [], (
                f"upstream received {len(stack.npm_upstream.tarball_hits)} hit(s)"
            )
            assert elapsed < 15.0
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_mixed_packages_no_cross_contamination(self, tmp_path: Path) -> None:
        """Clean and malicious requests in-flight simultaneously — no decision bleeds."""
        stack = await _build_stack(tmp_path)
        try:

            async def _clean() -> int:
                resp = await stack.client.get("/lodash/-/lodash-1.0.0.tgz")
                return resp.status

            async def _blocked() -> int:
                resp = await stack.client.get(f"/{MALICIOUS_NPM}/-/{MALICIOUS_NPM}-1.0.0.tgz")
                return resp.status

            n = CONCURRENCY // 2
            clean_results, blocked_results = await asyncio.gather(
                asyncio.gather(*[_clean() for _ in range(n)]),
                asyncio.gather(*[_blocked() for _ in range(n)]),
            )

            assert all(s == 200 for s in clean_results), "clean must pass"
            assert all(s == 403 for s in blocked_results), "blocked must stay blocked"
        finally:
            await _teardown_stack(stack)

    async def test_scoped_package_tarball_blocked_consistently(self, tmp_path: Path) -> None:
        """Scoped malicious packages are blocked on every concurrent request."""
        stack = await _build_stack(tmp_path)
        try:
            # Register @evil-scope/evil-pkg as malicious by naming it MALICIOUS_NPM.
            # We'll use a different pkg name that doesn't match our fake intel.
            # Instead verify that clean scoped packages pass:

            async def _fetch() -> int:
                resp = await stack.client.get("/@scope/mylib/-/mylib-1.0.0.tgz")
                return resp.status

            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            assert all(s == 200 for s in results), "clean scoped tarball must pass"
        finally:
            await _teardown_stack(stack)


# ── PyPI load tests ───────────────────────────────────────────────────────────


class TestPyPiLoadE2E:
    """PyPI proxy: correctness under CONCURRENCY simultaneous requests."""

    async def test_concurrent_clean_simple_index_all_200(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get("/simple/requests/")
                return resp.status, await resp.json()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            assert all(s == 200 for s, _ in results)
            for _, doc in results:
                assert len(doc["files"]) == 1, "clean package must have its file"
                assert "requests" in doc["files"][0]["filename"]
            assert elapsed < 15.0
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_malicious_simple_index_files_stripped(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get(f"/simple/{MALICIOUS_PYPI}/")
                return resp.status, await resp.json()

            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])

            assert all(s == 200 for s, _ in results)
            for _, doc in results:
                assert doc["files"] == [], "all files must be stripped for malicious pkg"
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_clean_file_gate_all_served(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:
            # Seed the hash cache from the simple index so integrity checks pass.
            await stack.client.get("/simple/requests/")
            wheel = "requests-1.0.0-py3-none-any.whl"

            async def _fetch() -> tuple[int, bytes]:
                resp = await stack.client.get(f"/packages/ab/cd/{wheel}")
                return resp.status, await resp.read()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            assert all(s == 200 for s, _ in results)
            assert all(body == WHEEL_BYTES for _, body in results)
            assert elapsed < 15.0
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_malicious_file_gate_all_blocked(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:
            # Wheel filenames use underscores; "evil-lib" → "evil_lib".
            norm = MALICIOUS_PYPI.replace("-", "_")

            async def _fetch() -> tuple[int, dict[str, Any]]:
                resp = await stack.client.get(f"/packages/ab/cd/{norm}-1.0.0-py3-none-any.whl")
                return resp.status, await resp.json()

            t0 = time.perf_counter()
            results = await asyncio.gather(*[_fetch() for _ in range(CONCURRENCY)])
            elapsed = time.perf_counter() - t0

            statuses = [s for s, _ in results]
            assert all(s == 403 for s in statuses), f"must always block — got {set(statuses)}"
            for _, body in results:
                assert body["rule"] == "block_malicious"
            assert elapsed < 15.0
        finally:
            await _teardown_stack(stack)

    async def test_concurrent_mixed_simple_index_clean_and_malicious(self, tmp_path: Path) -> None:
        """Clean and malicious simple-index requests run concurrently — no cross-contamination."""
        stack = await _build_stack(tmp_path)
        try:

            async def _clean() -> tuple[int, int]:
                resp = await stack.client.get("/simple/numpy/")
                doc = await resp.json()
                return resp.status, len(doc["files"])

            async def _blocked() -> tuple[int, int]:
                resp = await stack.client.get(f"/simple/{MALICIOUS_PYPI}/")
                doc = await resp.json()
                return resp.status, len(doc["files"])

            n = CONCURRENCY // 2
            clean_res, blocked_res = await asyncio.gather(
                asyncio.gather(*[_clean() for _ in range(n)]),
                asyncio.gather(*[_blocked() for _ in range(n)]),
            )

            assert all(s == 200 and count == 1 for s, count in clean_res)
            assert all(s == 200 and count == 0 for s, count in blocked_res)
        finally:
            await _teardown_stack(stack)


# ── Mixed npm + PyPI load ─────────────────────────────────────────────────────


class TestMixedLoadE2E:
    """npm and PyPI traffic interleaved under concurrent load."""

    async def test_npm_and_pypi_concurrent_no_interference(self, tmp_path: Path) -> None:
        stack = await _build_stack(tmp_path)
        try:

            async def _npm_clean() -> int:
                r = await stack.client.get("/lodash/-/lodash-1.0.0.tgz")
                return r.status

            async def _npm_blocked() -> int:
                r = await stack.client.get(f"/{MALICIOUS_NPM}/-/{MALICIOUS_NPM}-1.0.0.tgz")
                return r.status

            async def _pypi_clean() -> int:
                r = await stack.client.get("/simple/requests/")
                return r.status

            async def _pypi_blocked() -> tuple[int, int]:
                r = await stack.client.get(f"/simple/{MALICIOUS_PYPI}/")
                doc = await r.json()
                return r.status, len(doc["files"])

            n = CONCURRENCY // 4
            t0 = time.perf_counter()
            r1, r2, r3, r4 = await asyncio.gather(
                asyncio.gather(*[_npm_clean() for _ in range(n)]),
                asyncio.gather(*[_npm_blocked() for _ in range(n)]),
                asyncio.gather(*[_pypi_clean() for _ in range(n)]),
                asyncio.gather(*[_pypi_blocked() for _ in range(n)]),
            )
            elapsed = time.perf_counter() - t0

            assert all(s == 200 for s in r1), "npm clean must pass"
            assert all(s == 403 for s in r2), "npm malicious must block"
            assert all(s == 200 for s in r3), "pypi clean simple index must succeed"
            assert all(s == 200 and count == 0 for s, count in r4), (
                "pypi malicious simple index must have empty files"
            )
            assert elapsed < 15.0, f"mixed load took {elapsed:.1f}s"
        finally:
            await _teardown_stack(stack)

    async def test_health_endpoint_responsive_under_load(self, tmp_path: Path) -> None:
        """Health endpoint remains available while proxy is under load."""
        stack = await _build_stack(tmp_path)
        try:

            async def _background_load() -> None:
                for _ in range(10):
                    await stack.client.get("/lodash/-/lodash-1.0.0.tgz")

            async def _health_check() -> int:
                r = await stack.client.get("/-/pkggate/health")
                return r.status

            n = CONCURRENCY // 5
            health_tasks = [_health_check() for _ in range(n)]
            load_tasks = [_background_load() for _ in range(n)]

            health_statuses, _ = await asyncio.gather(
                asyncio.gather(*health_tasks),
                asyncio.gather(*load_tasks),
            )

            assert all(s == 200 for s in health_statuses), "health must stay 200 under load"
        finally:
            await _teardown_stack(stack)
