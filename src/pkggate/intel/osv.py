"""OSV.dev threat intel client.

Queries the OSV.dev v1 query endpoint for MAL-* advisories.
https://google.github.io/osv.dev/post-v1-query/
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp
from cachetools import TTLCache

from . import CLEAN, UNKNOWN, Verdict

log = logging.getLogger(__name__)


class OsvIntel:
    """OSV.dev-based intel source.

    A package@version combination is considered malicious when OSV returns
    at least one vulnerability whose primary id starts with ``MAL-``.
    """

    def __init__(
        self,
        api_url: str = "https://api.osv.dev/v1/query",
        timeout: float = 5.0,
        fail_closed: bool = True,
        cache_ttl: int = 3600,
        cache_size: int = 10_000,
    ) -> None:
        self._api_url = api_url
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._fail_closed = fail_closed
        self._cache: TTLCache[tuple[str, str, str], Verdict] = TTLCache(
            maxsize=cache_size, ttl=cache_ttl
        )
        self._session: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            async with self._lock:
                if self._session is None or self._session.closed:
                    self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self._session

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        key = (ecosystem, name, version)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        payload: dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version,
        }

        try:
            session = await self._ensure_session()
            async with session.post(self._api_url, json=payload) as resp:
                if resp.status != 200:
                    log.warning("OSV returned status %s for %s@%s", resp.status, name, version)
                    return self._degraded()
                data = await resp.json()
        except (TimeoutError, aiohttp.ClientError) as exc:
            log.warning("OSV query failed for %s@%s: %s", name, version, exc)
            return self._degraded()

        verdict = self._evaluate(data)
        self._cache[key] = verdict
        return verdict

    @staticmethod
    def _evaluate(data: dict[str, Any]) -> Verdict:
        vulns = data.get("vulns") or []
        for v in vulns:
            vid = v.get("id", "")
            if vid.startswith("MAL-"):
                return Verdict(
                    malicious=True,
                    reason="osv_malicious_advisory",
                    advisory_id=vid,
                )
        # Non-MAL vulns are ignored here; they are vulnerability advisories,
        # not malware flags. A separate policy rule can handle them.
        return CLEAN

    def _degraded(self) -> Verdict:
        if self._fail_closed:
            return Verdict(malicious=True, reason="intel_unavailable")
        return UNKNOWN

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
