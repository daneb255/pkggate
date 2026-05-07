"""npm registry proxy logic.

Handles two request kinds:

1. Metadata document (``GET /<pkg>`` or ``GET /@scope/<pkg>``):
   Fetches from upstream, then for each version in ``versions``:
     - checks threat intel
     - evaluates policy
   Versions whose policy decision is 'deny' are removed from the ``versions``
   map and the matching entries in ``time`` and ``dist-tags`` are cleaned up
   so the client never tries to resolve them.

2. Tarball (``GET /<pkg>/-/<file>-<ver>.tgz``):
   Re-evaluates policy as a final gate. If denied, returns 403 without
   streaming the body. Integrity of untouched tarballs is preserved, so
   lockfile-based installs keep working.

Other paths (search, login, dist-tags API, etc.) are transparently proxied.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp
from aiohttp import web

from ..audit import AuditLogger
from ..intel import IntelSource
from ..policy import PolicyEngine
from ..policy.rules import Decision, EvalContext
from ..utils import parse_metadata_path, parse_tarball_path

log = logging.getLogger(__name__)

ECOSYSTEM = "npm"

# Hop-by-hop headers (RFC 7230 §6.1) we must not forward as-is.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "content-encoding",
    }
)


class NpmProxy:
    def __init__(
        self,
        *,
        upstream: str,
        intel: IntelSource,
        policy: PolicyEngine,
        audit: AuditLogger,
        upstream_timeout: float = 30.0,
    ) -> None:
        self._upstream = upstream.rstrip("/")
        self._intel = intel
        self._policy = policy
        self._audit = audit
        self._timeout = aiohttp.ClientTimeout(total=upstream_timeout)
        self._session: aiohttp.ClientSession | None = None

    async def startup(self) -> None:
        self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def shutdown(self) -> None:
        if self._session is not None:
            await self._session.close()
        await self._intel.close()

    # -- aiohttp entry point -------------------------------------------------

    async def handle(self, request: web.Request) -> web.StreamResponse:
        path = request.match_info.get("path", "")
        client_ip = request.remote

        tarball = parse_tarball_path("/" + path)
        if tarball is not None:
            return await self._handle_tarball(request, tarball.name, tarball.version, client_ip)

        meta = parse_metadata_path("/" + path)
        if meta is not None and request.method == "GET":
            return await self._handle_metadata(request, meta, client_ip)

        return await self._pass_through(request, path)

    # -- handlers ------------------------------------------------------------

    async def _handle_tarball(
        self,
        request: web.Request,
        name: str,
        version: str,
        client_ip: str | None,
    ) -> web.StreamResponse:
        verdict = await self._intel.check(ECOSYSTEM, name, version)
        ctx = EvalContext(name=name, version=version, ecosystem=ECOSYSTEM, intel=verdict)
        decision = self._policy.evaluate(ctx)

        await self._audit.log(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            decision=decision,
            request_kind="tarball",
            client_ip=client_ip,
        )

        if not decision.allow:
            return _block_response(name, version, decision)

        # Stream tarball from upstream.
        url = f"{self._upstream}/{request.match_info['path']}"
        assert self._session is not None
        async with self._session.get(
            url, headers=_clean_request_headers(request.headers)
        ) as upstream:
            resp = web.StreamResponse(
                status=upstream.status,
                headers=_clean_response_headers(upstream.headers),
            )
            await resp.prepare(request)
            async for chunk in upstream.content.iter_chunked(64 * 1024):
                await resp.write(chunk)
            await resp.write_eof()
            return resp

    async def _handle_metadata(
        self,
        request: web.Request,
        name: str,
        client_ip: str | None,
    ) -> web.Response:
        url = f"{self._upstream}/{request.match_info['path']}"
        assert self._session is not None
        async with self._session.get(
            url, headers=_clean_request_headers(request.headers)
        ) as upstream:
            if upstream.status != 200:
                body = await upstream.read()
                return web.Response(
                    status=upstream.status,
                    headers=_clean_response_headers(upstream.headers),
                    body=body,
                )
            try:
                doc: dict[str, Any] = await upstream.json(content_type=None)
            except aiohttp.ContentTypeError, json.JSONDecodeError:
                body = await upstream.read()
                return web.Response(
                    status=upstream.status,
                    headers=_clean_response_headers(upstream.headers),
                    body=body,
                )

        filtered, blocked = await self._filter_metadata(doc, name, client_ip)
        body = json.dumps(filtered).encode("utf-8")

        headers = _clean_response_headers(upstream.headers)
        headers["content-type"] = "application/json"
        headers["x-pkggate-blocked-versions"] = str(blocked)

        return web.Response(status=200, headers=headers, body=body)

    async def _pass_through(self, request: web.Request, path: str) -> web.StreamResponse:
        url = f"{self._upstream}/{path}"
        assert self._session is not None
        body = await request.read() if request.can_read_body else None
        async with self._session.request(
            request.method,
            url,
            headers=_clean_request_headers(request.headers),
            data=body,
            params=request.rel_url.query,
        ) as upstream:
            content = await upstream.read()
            return web.Response(
                status=upstream.status,
                headers=_clean_response_headers(upstream.headers),
                body=content,
            )

    # -- metadata filtering --------------------------------------------------

    async def _filter_metadata(
        self,
        doc: dict[str, Any],
        name: str,
        client_ip: str | None,
    ) -> tuple[dict[str, Any], int]:
        versions: dict[str, Any] = doc.get("versions") or {}
        times: dict[str, Any] = doc.get("time") or {}

        blocked_versions: list[str] = []

        for version, manifest in list(versions.items()):
            verdict = await self._intel.check(ECOSYSTEM, name, version)

            # Stitch publication timestamp so age rule can use it.
            if isinstance(manifest, dict):
                published = times.get(version)
                if published:
                    manifest = dict(manifest)
                    manifest["_published_at"] = published

            ctx = EvalContext(
                name=name,
                version=version,
                ecosystem=ECOSYSTEM,
                version_manifest=manifest if isinstance(manifest, dict) else None,
                intel=verdict,
            )
            decision = self._policy.evaluate(ctx)

            await self._audit.log(
                ecosystem=ECOSYSTEM,
                name=name,
                version=version,
                decision=decision,
                request_kind="metadata",
                client_ip=client_ip,
            )

            if not decision.allow:
                blocked_versions.append(version)

        if not blocked_versions:
            return doc, 0

        # Remove blocked versions from versions map and time map.
        for v in blocked_versions:
            versions.pop(v, None)
            times.pop(v, None)

        # Clean dist-tags pointing at removed versions. If 'latest' gets
        # removed, fall back to the highest remaining version lexicographically
        # (the client re-sorts by semver anyway, but npm expects something).
        dist_tags: dict[str, Any] = doc.get("dist-tags") or {}
        for tag, v in list(dist_tags.items()):
            if v in blocked_versions:
                dist_tags.pop(tag, None)
        if "latest" not in dist_tags and versions:
            dist_tags["latest"] = max(versions.keys())

        doc["versions"] = versions
        doc["time"] = times
        doc["dist-tags"] = dist_tags
        return doc, len(blocked_versions)


# -- helpers ------------------------------------------------------------------


def _block_response(name: str, version: str, decision: Decision) -> web.Response:
    body = {
        "error": "blocked_by_pkggate",
        "package": name,
        "version": version,
        "rule": decision.rule,
        "reason": decision.reason,
        "source": decision.source,
    }
    return web.json_response(body, status=403)


def _clean_request_headers(headers: Any) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}


def _clean_response_headers(headers: Any) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP}
