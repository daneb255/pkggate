import pytest
from aioresponses import aioresponses

from pkggate.intel.osv import OsvIntel

OSV_URL = "https://api.osv.dev/v1/query"


@pytest.mark.asyncio
async def test_detects_mal_advisory() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True)
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={"vulns": [{"id": "MAL-2024-88", "summary": "malicious"}]},
        )
        v = await intel.check("npm", "passports-js", "0.0.1-security")
    assert v.malicious is True
    assert v.advisory_id == "MAL-2024-88"
    assert v.reason == "osv_malicious_advisory"
    await intel.close()


@pytest.mark.asyncio
async def test_ignores_non_mal_vulnerabilities() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True)
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]},
        )
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.malicious is False
    await intel.close()


@pytest.mark.asyncio
async def test_clean_response() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True)
    with aioresponses() as m:
        m.post(OSV_URL, status=200, payload={})
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.malicious is False
    assert v.reason == "clean"
    await intel.close()


@pytest.mark.asyncio
async def test_fail_closed_on_error() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True)
    with aioresponses() as m:
        m.post(OSV_URL, status=500)
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.malicious is True
    assert v.reason == "intel_unavailable"
    await intel.close()


@pytest.mark.asyncio
async def test_fail_open_on_error() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=False)
    with aioresponses() as m:
        m.post(OSV_URL, status=500)
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.malicious is False
    assert v.reason == "unknown"
    await intel.close()


@pytest.mark.asyncio
async def test_cache_hit_avoids_second_request() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True, cache_ttl=60)
    with aioresponses() as m:
        m.post(OSV_URL, status=200, payload={"vulns": []})
        v1 = await intel.check("npm", "lodash", "4.17.21")
        v2 = await intel.check("npm", "lodash", "4.17.21")
    assert v1.malicious is False
    assert v2.malicious is False
    await intel.close()
