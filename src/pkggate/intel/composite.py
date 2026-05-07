"""Composite intel source.

Tries the local OSV mirror first (fast path, zero network). On a clean
verdict, optionally falls back to the live OSV API to catch advisories
that were published after the last mirror refresh.

This addresses the zero-day gap: the mirror refresh interval is typically
an hour, but fresh malware can land on npm in minutes. A small number of
live API calls for clean-by-mirror lookups gives us both speed and coverage.
"""

from __future__ import annotations

from . import CLEAN, Verdict
from .mirror import OsvMirror
from .osv import OsvIntel


class CompositeIntel:
    def __init__(
        self,
        mirror: OsvMirror,
        live: OsvIntel | None = None,
        live_fallback_for_clean: bool = True,
    ) -> None:
        self._mirror = mirror
        self._live = live
        self._live_fallback = live_fallback_for_clean and live is not None

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        if ecosystem not in self._mirror.ecosystems:
            if self._live is not None:
                return await self._live.check(ecosystem, name, version)
            return CLEAN

        v = await self._mirror.check(ecosystem, name, version)
        if v.malicious:
            return v
        if self._live_fallback and self._live is not None:
            return await self._live.check(ecosystem, name, version)
        return v

    async def close(self) -> None:
        await self._mirror.stop()
        if self._live is not None:
            await self._live.close()
