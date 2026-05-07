"""Tarball-vs-manifest integrity verification."""

from __future__ import annotations

import base64
import hashlib

import pytest

from pkggate.proxy.integrity import Integrity, IntegrityMismatchError, parse_dist


def _sri(algo: str, payload: bytes) -> str:
    digest = hashlib.new(algo, payload).digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


class TestParseDist:
    def test_sri_sha512(self) -> None:
        payload = b"hello"
        claim = parse_dist({"integrity": _sri("sha512", payload)})
        assert claim is not None
        assert claim.algorithm == "sha512"
        claim.verify(payload)

    def test_sri_picks_strongest_when_multiple(self) -> None:
        payload = b"hello"
        sri = " ".join([_sri("sha256", payload), _sri("sha512", payload)])
        claim = parse_dist({"integrity": sri})
        assert claim is not None
        assert claim.algorithm == "sha512"

    def test_legacy_shasum(self) -> None:
        payload = b"hello"
        sha1 = hashlib.sha1(payload).hexdigest()
        claim = parse_dist({"shasum": sha1})
        assert claim is not None
        assert claim.algorithm == "sha1"
        claim.verify(payload)

    def test_prefers_sri_over_shasum(self) -> None:
        payload = b"hello"
        claim = parse_dist(
            {
                "integrity": _sri("sha256", payload),
                "shasum": "0" * 40,  # bogus, but should be ignored
            }
        )
        assert claim is not None
        assert claim.source == "integrity"
        claim.verify(payload)

    @pytest.mark.parametrize(
        "dist",
        [
            None,
            {},
            {"integrity": ""},
            {"integrity": "md5-abc"},  # disallowed algo
            {"integrity": "sha256-not_base64!!"},
            {"shasum": "tooshort"},
            "not-a-dict",
        ],
    )
    def test_unparseable_returns_none(self, dist: object) -> None:
        assert parse_dist(dist) is None  # type: ignore[arg-type]


class TestVerify:
    def test_mismatch_raises(self) -> None:
        claim = Integrity(
            algorithm="sha256",
            digest=hashlib.sha256(b"good").digest(),
            source="integrity",
        )
        with pytest.raises(IntegrityMismatchError):
            claim.verify(b"tampered")
