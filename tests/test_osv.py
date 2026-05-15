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
async def test_extracts_cvss_v3_score() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=False)
    # CVSS:3.1 vector for a critical vuln (base score 9.8)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={
                "vulns": [
                    {
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "severity": [{"type": "CVSS_V3", "score": vector}],
                    }
                ]
            },
        )
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.malicious is False
    assert v.max_cvss is not None
    assert abs(v.max_cvss - 9.8) < 0.1
    await intel.close()


@pytest.mark.asyncio
async def test_extracts_max_cvss_across_multiple_vulns() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=False)
    low_vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"   # low score
    high_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={
                "vulns": [
                    {"id": "CVE-A", "severity": [{"type": "CVSS_V3", "score": low_vector}]},
                    {"id": "CVE-B", "severity": [{"type": "CVSS_V3", "score": high_vector}]},
                ]
            },
        )
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.max_cvss is not None
    assert abs(v.max_cvss - 9.8) < 0.1
    await intel.close()


@pytest.mark.asyncio
async def test_no_cvss_when_severity_absent() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=False)
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={"vulns": [{"id": "GHSA-no-severity"}]},
        )
        v = await intel.check("npm", "lodash", "4.17.21")
    assert v.max_cvss is None
    await intel.close()


@pytest.mark.asyncio
async def test_mal_advisory_carries_cvss_score() -> None:
    intel = OsvIntel(api_url=OSV_URL, fail_closed=True)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with aioresponses() as m:
        m.post(
            OSV_URL,
            status=200,
            payload={
                "vulns": [
                    {
                        "id": "MAL-2024-88",
                        "severity": [{"type": "CVSS_V3", "score": vector}],
                    }
                ]
            },
        )
        v = await intel.check("npm", "evil-pkg", "1.0.0")
    assert v.malicious is True
    assert v.advisory_id == "MAL-2024-88"
    assert v.max_cvss is not None
    assert abs(v.max_cvss - 9.8) < 0.1
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
