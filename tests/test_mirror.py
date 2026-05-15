import io
import json
import zipfile
from datetime import datetime
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


class TestRefreshMetadata:
    """Tests for mirror refresh metadata tracking."""

    def test_refresh_count_tracking(self, tmp_path: Path) -> None:
        """Test that refresh count is tracked in metadata."""
        bundle = _make_bundle(
            [
                {
                    "id": "MAL-2024-88",
                    "affected": [
                        {
                            "package": {"name": "test-pkg", "ecosystem": "npm"},
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        )

        m = OsvMirror(db_path=tmp_path / "mirror.db")
        from pkggate.intel.mirror import _iter_mal_records

        advisories = list(_iter_mal_records(bundle))
        m._update_ecosystem("npm", advisories)

        # Check that refresh count was incremented
        with m._borrow() as conn:
            row = conn.execute(
                "SELECT refresh_count FROM ecosystem_refresh WHERE ecosystem = ?",
                ("npm",),
            ).fetchone()
            assert row is not None
            assert row[0] == 1

    def test_last_refresh_time_tracking(self, tmp_path: Path) -> None:
        """Test that last refresh time is stored."""
        bundle = _make_bundle(
            [
                {
                    "id": "MAL-2024-88",
                    "affected": [
                        {
                            "package": {"name": "test-pkg", "ecosystem": "npm"},
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        )

        m = OsvMirror(db_path=tmp_path / "mirror.db")
        from pkggate.intel.mirror import _iter_mal_records

        advisories = list(_iter_mal_records(bundle))
        m._update_ecosystem("npm", advisories)

        # Check that last_refresh_time was set
        last_time = m._get_last_refresh_time("npm")
        assert last_time is not None
        # Verify it's a valid ISO format datetime
        datetime.fromisoformat(last_time)

    def test_merge_advisories(self, tmp_path: Path) -> None:
        """Test that successive _update_ecosystem calls merge data instead of replacing."""
        # First: seed with initial advisories
        initial_bundle = _make_bundle(
            [
                {
                    "id": "MAL-2024-88",
                    "affected": [
                        {
                            "package": {"name": "pkg-a", "ecosystem": "npm"},
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        )

        m = OsvMirror(db_path=tmp_path / "mirror.db")
        from pkggate.intel.mirror import _iter_mal_records

        advisories = list(_iter_mal_records(initial_bundle))
        m._update_ecosystem("npm", advisories)

        # Verify initial data
        v1 = m._check_sync("npm", "pkg-a", "1.0.0")
        assert v1.malicious is True

        # Now add new advisory via incremental
        new_advisory = {
            "id": "MAL-2025-100",
            "affected": [
                {
                    "package": {"name": "pkg-b", "ecosystem": "npm"},
                    "versions": ["2.0.0"],
                }
            ],
        }
        m._update_ecosystem("npm", [new_advisory])

        # Both advisories should exist
        v1_after = m._check_sync("npm", "pkg-a", "1.0.0")
        assert v1_after.malicious is True
        assert v1_after.advisory_id == "MAL-2024-88"

        v2 = m._check_sync("npm", "pkg-b", "2.0.0")
        assert v2.malicious is True
        assert v2.advisory_id == "MAL-2025-100"
