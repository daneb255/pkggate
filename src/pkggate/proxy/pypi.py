"""PyPI proxy.

pip talks to the PEP 503 / PEP 691 "Simple repository" API. We expose two
routes:

1. ``GET /simple/<project>/`` — fetched from the upstream simple index in
   PEP 691 JSON form. Each file entry encodes a project version in its
   filename; we run intel + policy per version, drop denied files, rewrite
   surviving file URLs through this proxy so the second gate can fire, and
   harvest the SHA-256 hash from the response for later integrity checks.

2. ``GET /packages/<path>`` — the actual file fetch. We re-evaluate policy
   for the file's version (last gate before bytes leave the proxy) and
   verify the SHA-256 hash against the simple-index claim. Lockfile-driven
   installs that hit this route without first browsing the index trigger a
   one-shot lookup of the parent project's index to populate the hash cache.

The OSV ecosystem string is "PyPI" (case-sensitive — that's what OSV uses).
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from urllib.parse import urlparse

import aiohttp
from aiohttp import web
from cachetools import TTLCache
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

from ..audit import AuditLogger
from ..intel import IntelSource
from ..policy import PolicyEngine
from ..policy.rules import Decision, EvalContext

log = logging.getLogger(__name__)

ECOSYSTEM = "PyPI"

_SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"


class PyPiProxy:
    """PyPI Simple-API proxy with policy and integrity gates."""

    def __init__(
        self,
        *,
        upstream_simple: str,
        upstream_files: str,
        intel: IntelSource,
        policy: PolicyEngine,
        audit: AuditLogger,
        public_base_url: str,
        upstream_timeout: float = 30.0,
        verify_integrity: bool = True,
        tarball_max_buffer_bytes: int = 200 * 1024 * 1024,
    ) -> None:
        self._upstream_simple = upstream_simple.rstrip("/") + "/"
        self._upstream_files = upstream_files.rstrip("/") + "/"
        self._intel = intel
        self._policy = policy
        self._audit = audit
        self._public_base = public_base_url.rstrip("/")
        self._timeout = aiohttp.ClientTimeout(total=upstream_timeout)
        self._verify_integrity = verify_integrity
        self._tarball_max_bytes = tarball_max_buffer_bytes
        self._session: aiohttp.ClientSession | None = None
        # filename -> sha256 hex (from the simple index). Bounded.
        self._hash_cache: TTLCache[str, str] = TTLCache(maxsize=50_000, ttl=24 * 3600)

    async def startup(self) -> None:
        self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def shutdown(self) -> None:
        if self._session is not None:
            await self._session.close()

    def register(self, app: web.Application) -> None:
        app.router.add_get("/simple/{project}", self.handle_simple)
        app.router.add_get("/simple/{project}/", self.handle_simple)
        app.router.add_get("/packages/{path:.*}", self.handle_file)

    # -- simple index --------------------------------------------------------

    async def handle_simple(self, request: web.Request) -> web.Response:
        project = canonicalize_name(request.match_info["project"])
        url = f"{self._upstream_simple}{project}/"
        assert self._session is not None
        try:
            async with self._session.get(url, headers={"accept": _SIMPLE_ACCEPT}) as resp:
                if resp.status != 200:
                    body = await resp.read()
                    return web.Response(
                        status=resp.status,
                        body=body,
                        headers={"content-type": resp.headers.get("content-type", "text/plain")},
                    )
                doc = await resp.json(content_type=None)
        except (TimeoutError, aiohttp.ClientError) as exc:
            log.warning("pypi simple fetch failed for %s: %s", project, exc)
            return web.json_response({"error": "upstream_unavailable"}, status=502)

        filtered = await self._filter_simple(doc, project, request.remote)
        return web.Response(
            body=json.dumps(filtered).encode("utf-8"),
            content_type=_SIMPLE_ACCEPT,
        )

    async def _filter_simple(
        self, doc: dict[str, Any], project: str, client_ip: str | None
    ) -> dict[str, Any]:
        files: list[dict[str, Any]] = list(doc.get("files") or [])
        kept: list[dict[str, Any]] = []

        for entry in files:
            filename = entry.get("filename")
            if not isinstance(filename, str):
                continue

            version = _version_from_filename(project, filename)
            if version is None:
                # Unparseable — keep it but skip checks rather than block all
                # installs because of one weird filename.
                kept.append(entry)
                continue

            verdict = await self._intel.check(ECOSYSTEM, project, version)
            ctx = EvalContext(
                name=project,
                version=version,
                ecosystem=ECOSYSTEM,
                version_manifest=None,
                intel=verdict,
            )
            decision = self._policy.evaluate(ctx)

            await self._audit.log(
                ecosystem=ECOSYSTEM,
                name=project,
                version=version,
                decision=decision,
                request_kind="simple_index",
                client_ip=client_ip,
            )

            if not decision.allow:
                _log_block(ECOSYSTEM, project, version, decision)
                continue

            # Harvest hash for the second gate, then rewrite the URL through us.
            sha256 = (entry.get("hashes") or {}).get("sha256")
            if isinstance(sha256, str):
                self._hash_cache[filename] = sha256

            original = entry.get("url")
            if isinstance(original, str):
                rewritten = self._rewrite_file_url(original)
                if rewritten is not None:
                    entry = dict(entry)
                    entry["url"] = rewritten

            kept.append(entry)

        blocked = len(files) - len(kept)
        if blocked:
            log.info(
                "BLOCK  [PyPI] simple %s: %d of %d file(s) removed",
                project,
                blocked,
                len(files),
            )
        out = dict(doc)
        out["files"] = kept
        return out

    def _rewrite_file_url(self, url: str) -> str | None:
        """Map an upstream file URL onto our /packages/ route.

        URLs from files.pythonhosted.org look like
        ``https://files.pythonhosted.org/packages/<hash>/<filename>``. We keep
        the path tail and serve via ``{public_base}/packages/<hash>/<filename>``
        so the second gate fires.
        """
        try:
            parsed = urlparse(url)
        except ValueError:
            return None
        path = parsed.path.lstrip("/")
        if not path.startswith("packages/"):
            return None
        return f"{self._public_base}/{path}"

    # -- file fetch ----------------------------------------------------------

    async def handle_file(self, request: web.Request) -> web.StreamResponse:
        path = request.match_info["path"]
        filename = path.rsplit("/", 1)[-1]
        client_ip = request.remote

        project, version = _parse_file_identity(filename)
        if project is None or version is None:
            # Don't know what to evaluate — pass through with audit log only.
            return await self._stream_file(request, "packages/" + path, expected_sha256=None)

        verdict = await self._intel.check(ECOSYSTEM, project, version)
        decision = self._policy.evaluate(
            EvalContext(name=project, version=version, ecosystem=ECOSYSTEM, intel=verdict)
        )
        await self._audit.log(
            ecosystem=ECOSYSTEM,
            name=project,
            version=version,
            decision=decision,
            request_kind="file",
            client_ip=client_ip,
        )
        if not decision.allow:
            _log_block(ECOSYSTEM, project, version, decision)
            return _block_response(project, version, decision)

        log.info("ALLOW  [PyPI] file %s@%s", project, version)
        expected = self._hash_cache.get(filename)
        if expected is None and self._verify_integrity:
            await self._prefetch_hash(project, filename)
            expected = self._hash_cache.get(filename)

        return await self._stream_file(
            request,
            "packages/" + path,
            expected_sha256=expected if self._verify_integrity else None,
            project=project,
            version=version,
            client_ip=client_ip,
        )

    async def _prefetch_hash(self, project: str, filename: str) -> None:
        """Fetch the parent project's simple index once to fill the hash cache."""
        url = f"{self._upstream_simple}{project}/"
        assert self._session is not None
        try:
            async with self._session.get(url, headers={"accept": _SIMPLE_ACCEPT}) as resp:
                if resp.status != 200:
                    return
                doc = await resp.json(content_type=None)
        except (TimeoutError, aiohttp.ClientError) as exc:
            log.warning("pypi hash prefetch failed for %s: %s", project, exc)
            return

        for entry in doc.get("files") or []:
            fn = entry.get("filename")
            sha = (entry.get("hashes") or {}).get("sha256")
            if isinstance(fn, str) and isinstance(sha, str):
                self._hash_cache[fn] = sha

    async def _stream_file(
        self,
        request: web.Request,
        path: str,
        *,
        expected_sha256: str | None,
        project: str | None = None,
        version: str | None = None,
        client_ip: str | None = None,
    ) -> web.StreamResponse:
        url = f"{self._upstream_files}{path}"
        assert self._session is not None
        async with self._session.get(url) as upstream:
            if upstream.status != 200:
                body = await upstream.read()
                return web.Response(status=upstream.status, body=body)

            cap = self._tarball_max_bytes
            chunks: list[bytes] = []
            size = 0
            async for chunk in upstream.content.iter_chunked(64 * 1024):
                size += len(chunk)
                if size > cap:
                    if project and version:
                        await self._audit.log(
                            ecosystem=ECOSYSTEM,
                            name=project,
                            version=version,
                            decision=Decision.deny(
                                "file_too_large",
                                f"file exceeds {cap} byte verification cap",
                            ),
                            request_kind="file",
                            client_ip=client_ip,
                        )
                    return web.json_response(
                        {"error": "blocked_by_pkggate", "reason": "file_too_large"},
                        status=502,
                    )
                chunks.append(chunk)
            body = b"".join(chunks)

        if expected_sha256 is not None:
            actual = hashlib.sha256(body).hexdigest()
            if actual.lower() != expected_sha256.lower():
                if project and version:
                    await self._audit.log(
                        ecosystem=ECOSYSTEM,
                        name=project,
                        version=version,
                        decision=Decision.deny(
                            "integrity_mismatch",
                            f"sha256 mismatch: expected {expected_sha256[:16]}…"
                            f", got {actual[:16]}…",
                            source="simple_index",
                        ),
                        request_kind="file",
                        client_ip=client_ip,
                    )
                log.warning(
                    "pypi integrity mismatch for %s: expected %s got %s",
                    path,
                    expected_sha256,
                    actual,
                )
                return web.json_response(
                    {
                        "error": "blocked_by_pkggate",
                        "rule": "integrity_mismatch",
                        "reason": "sha256 hash does not match simple-index claim",
                    },
                    status=502,
                )

        return web.Response(status=200, body=body)


# -- helpers -----------------------------------------------------------------


def _log_block(ecosystem: str, name: str, version: str, decision: Decision) -> None:
    src = f" source={decision.source}" if decision.source else ""
    log.warning(
        "BLOCK  [%s] %s@%s rule=%s reason=%s%s",
        ecosystem,
        name,
        version,
        decision.rule,
        decision.reason,
        src,
    )


def _block_response(name: str, version: str, decision: Decision) -> web.Response:
    return web.json_response(
        {
            "error": "blocked_by_pkggate",
            "package": name,
            "version": version,
            "rule": decision.rule,
            "reason": decision.reason,
            "source": decision.source,
        },
        status=403,
    )


def _version_from_filename(project: str, filename: str) -> str | None:
    """Extract version from a wheel or sdist filename (PEP 427 / PEP 625)."""
    parsed = _parse_file_identity(filename)
    if parsed[0] is None:
        return None
    if canonicalize_name(parsed[0]) != canonicalize_name(project):
        # Filename doesn't match the project we're filtering — defensive.
        return None
    return parsed[1]


def _parse_file_identity(filename: str) -> tuple[str | None, str | None]:
    """Return (project, version) for a wheel or sdist, or (None, None)."""
    if filename.endswith(".whl"):
        try:
            name, version, *_ = parse_wheel_filename(filename)
            return name, str(version)
        except InvalidWheelFilename, ValueError:
            return None, None
    # parse_sdist_filename handles .tar.gz and .zip per PEP 625.
    try:
        name, version = parse_sdist_filename(filename)
        return name, str(version)
    except InvalidSdistFilename, ValueError:
        return None, None
