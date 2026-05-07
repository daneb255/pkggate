import io
import json
import zipfile
from pathlib import Path

import pytest

from pkggate.intel.mirror import OsvMirror, _version_in_range


def _make_bundle(records: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for r in records:
            zf.writestr(f"{r['id']}.json", json.dumps(r))
        # include a non-MAL record to prove filtering
        zf.writestr(
            "GHSA-aaaa-bbbb-cccc.json",
            json.dumps({"id": "GHSA-aaaa-bbbb-cccc", "affected": []}),
        )
    return buf.getvalue()


@pytest.fixture
def mirror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> OsvMirror:
    bundle = _make_bundle(
        [
            {
                "id": "MAL-2024-88",
                "affected": [
                    {
                        "package": {"name": "passports-js", "ecosystem": "npm"},
                        "versions": ["0.0.1-security"],
                    }
                ],
            },
            {
                "id": "MAL-2025-47199",
                "affected": [
                    {
                        "package": {"name": "ngx-toastr", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "19.0.1"},
                                    {"last_affected": "19.0.2"},
                                ],
                            }
                        ],
                    }
                ],
            },
        ]
    )

    m = OsvMirror(db_path=tmp_path / "mirror.db")
    from pkggate.intel.mirror import _iter_mal_records

    advisories = list(_iter_mal_records(bundle))
    m._replace("npm", advisories)
    return m


class TestExactMatch:
    def test_known_malicious(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "passports-js", "0.0.1-security")
        assert v.malicious is True
        assert v.advisory_id == "MAL-2024-88"

    def test_different_version_clean(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "passports-js", "1.0.0")
        assert v.malicious is False

    def test_unknown_package_clean(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "lodash", "4.17.21")
        assert v.malicious is False


class TestRangeMatch:
    def test_within_range_blocks(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "ngx-toastr", "19.0.2")
        assert v.malicious is True
        assert v.advisory_id == "MAL-2025-47199"

    def test_below_range_clean(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "ngx-toastr", "19.0.0")
        assert v.malicious is False

    def test_above_range_clean(self, mirror: OsvMirror) -> None:
        v = mirror._check_sync("npm", "ngx-toastr", "19.0.3")
        assert v.malicious is False


class TestRangeLogic:
    def test_open_introduced(self) -> None:
        assert _version_in_range("1.2.3", "0", None, None) is True

    def test_before_introduced(self) -> None:
        assert _version_in_range("1.0.0", "2.0.0", None, None) is False

    def test_after_fixed(self) -> None:
        assert _version_in_range("2.0.0", "1.0.0", "2.0.0", None) is False

    def test_at_last_affected(self) -> None:
        assert _version_in_range("1.5.0", "1.0.0", None, "1.5.0") is True

    def test_beyond_last_affected(self) -> None:
        assert _version_in_range("1.6.0", "1.0.0", None, "1.5.0") is False

    def test_invalid_version(self) -> None:
        assert _version_in_range("not-a-version", "0", None, None) is False
