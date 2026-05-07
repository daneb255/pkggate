"""Tests for CompositeIntel routing behaviour.

The composite wraps a mirror (sync, local) and an optional live client
(async, HTTP). We verify the routing without hitting any network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkggate.intel import CLEAN, Verdict
from pkggate.intel.composite import CompositeIntel
from pkggate.intel.mirror import OsvMirror


class _FakeLive:
    def __init__(self, verdict: Verdict | None = None) -> None:
        self._verdict = verdict if verdict is not None else CLEAN
        self.calls: list[tuple[str, str, str]] = []

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        self.calls.append((ecosystem, name, version))
        return self._verdict

    async def close(self) -> None:
        return None


@pytest.fixture
def empty_mirror(tmp_path: Path) -> OsvMirror:
    return OsvMirror(db_path=tmp_path / "empty.db")


@pytest.fixture
def loaded_mirror(tmp_path: Path) -> OsvMirror:
    m = OsvMirror(db_path=tmp_path / "loaded.db")
    m._replace(
        "npm",
        [
            {
                "id": "MAL-2024-88",
                "affected": [
                    {
                        "package": {"name": "passports-js", "ecosystem": "npm"},
                        "versions": ["0.0.1-security"],
                    }
                ],
            }
        ],
    )
    m._replace(
        "PyPI",
        [
            {
                "id": "MAL-2024-PYPI-1",
                "affected": [
                    {
                        "package": {"name": "malicious-pkg", "ecosystem": "PyPI"},
                        "versions": ["1.0.0"],
                    }
                ],
            }
        ],
    )
    return m


@pytest.mark.asyncio
async def test_mirror_hit_short_circuits(loaded_mirror: OsvMirror) -> None:
    live = _FakeLive()
    c = CompositeIntel(loaded_mirror, live=live, live_fallback_for_clean=True)
    v = await c.check("npm", "passports-js", "0.0.1-security")
    assert v.malicious is True
    assert v.advisory_id == "MAL-2024-88"
    assert live.calls == []


@pytest.mark.asyncio
async def test_mirror_clean_with_fallback_calls_live(empty_mirror: OsvMirror) -> None:
    live = _FakeLive(Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-X"))
    c = CompositeIntel(empty_mirror, live=live, live_fallback_for_clean=True)
    v = await c.check("npm", "lodash", "4.17.21")
    assert v.malicious is True
    assert v.advisory_id == "MAL-X"
    assert live.calls == [("npm", "lodash", "4.17.21")]


@pytest.mark.asyncio
async def test_mirror_clean_without_fallback_returns_clean(empty_mirror: OsvMirror) -> None:
    live = _FakeLive(Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-X"))
    c = CompositeIntel(empty_mirror, live=live, live_fallback_for_clean=False)
    v = await c.check("npm", "lodash", "4.17.21")
    assert v.malicious is False
    assert live.calls == []


@pytest.mark.asyncio
async def test_pypi_mirror_hit_blocks(loaded_mirror: OsvMirror) -> None:
    live = _FakeLive()
    c = CompositeIntel(loaded_mirror, live=live, live_fallback_for_clean=True)
    v = await c.check("PyPI", "malicious-pkg", "1.0.0")
    assert v.malicious is True
    assert v.advisory_id == "MAL-2024-PYPI-1"
    assert live.calls == []  # mirror hit — live never called


@pytest.mark.asyncio
async def test_pypi_mirror_clean_with_fallback_calls_live(loaded_mirror: OsvMirror) -> None:
    live = _FakeLive(Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-Y"))
    c = CompositeIntel(loaded_mirror, live=live, live_fallback_for_clean=True)
    v = await c.check("PyPI", "clean-pkg", "1.0.0")
    assert v.malicious is True
    assert live.calls == [("PyPI", "clean-pkg", "1.0.0")]


@pytest.mark.asyncio
async def test_unknown_ecosystem_defers_to_live(empty_mirror: OsvMirror) -> None:
    live = _FakeLive(Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-Y"))
    c = CompositeIntel(empty_mirror, live=live)
    v = await c.check("cargo", "rand", "0.8.5")
    assert v.malicious is True
    assert live.calls == [("cargo", "rand", "0.8.5")]


@pytest.mark.asyncio
async def test_unknown_ecosystem_without_live_is_clean(empty_mirror: OsvMirror) -> None:
    c = CompositeIntel(empty_mirror, live=None)
    v = await c.check("cargo", "rand", "0.8.5")
    assert v.malicious is False
