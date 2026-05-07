"""Tarball integrity verification against npm manifest hashes.

npm publishes two kinds of integrity metadata per version under ``dist``:

* ``integrity``: SRI string per https://www.w3.org/TR/SRI/, e.g.
  ``sha512-<base64>``. Modern (npm >= 5).
* ``shasum``: bare SHA-1 hex. Legacy.

We accept both. If neither is present (very old packages) we cannot verify and
the caller decides whether to fail open or block — the typical pkggate default
is fail-open for compatibility.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

# Algorithms permitted by the W3C SRI spec.
_SRI_ALGORITHMS = {"sha256", "sha384", "sha512"}


class IntegrityMismatchError(Exception):
    """Raised when a tarball's hash does not match the manifest's claim."""


@dataclass(frozen=True)
class Integrity:
    """A parsed integrity claim, normalised to (algorithm, raw digest bytes)."""

    algorithm: str  # "sha1", "sha256", "sha384", "sha512"
    digest: bytes
    source: str  # "integrity" or "shasum" — for diagnostics

    def verify(self, payload: bytes) -> None:
        actual = hashlib.new(self.algorithm, payload).digest()
        if actual != self.digest:
            raise IntegrityMismatchError(
                f"{self.algorithm} mismatch: expected {self.digest.hex()[:16]}…, "
                f"got {actual.hex()[:16]}…"
            )


def parse_dist(dist: dict | None) -> Integrity | None:
    """Best-effort parse of an npm version's ``dist`` block.

    Prefers the SRI ``integrity`` field. Falls back to legacy ``shasum``.
    Returns None if neither is parseable.
    """
    if not isinstance(dist, dict):
        return None

    sri = dist.get("integrity")
    if isinstance(sri, str):
        parsed = _parse_sri(sri)
        if parsed is not None:
            return parsed

    shasum = dist.get("shasum")
    if isinstance(shasum, str) and len(shasum) == 40:
        try:
            return Integrity(
                algorithm="sha1",
                digest=binascii.unhexlify(shasum),
                source="shasum",
            )
        except (binascii.Error, ValueError):
            return None

    return None


def _parse_sri(value: str) -> Integrity | None:
    # SRI may carry multiple space-separated hashes; take the strongest one.
    best: Integrity | None = None
    rank = {"sha256": 1, "sha384": 2, "sha512": 3}
    for token in value.split():
        algo, sep, b64 = token.partition("-")
        if not sep or algo not in _SRI_ALGORITHMS:
            continue
        try:
            digest = base64.b64decode(b64, validate=True)
        except binascii.Error:
            continue
        candidate = Integrity(algorithm=algo, digest=digest, source="integrity")
        if best is None or rank[algo] > rank[best.algorithm]:
            best = candidate
    return best
