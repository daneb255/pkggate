from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[a-zA-Z0-9.-]+))?(?:\+[a-zA-Z0-9.-]+)?$"
)
_NUMERIC_RE = re.compile(r"^\d+$")


class InvalidSemverError(ValueError):
    pass


def _compare_prerelease(a: tuple[str, ...], b: tuple[str, ...]) -> int:
    """Per semver §11.4: identifier-by-identifier; numeric < alphanumeric;
    shorter prefix < longer when otherwise equal."""
    for ia, ib in zip(a, b):
        a_num = _NUMERIC_RE.match(ia)
        b_num = _NUMERIC_RE.match(ib)
        if a_num and b_num:
            na, nb = int(ia), int(ib)
            if na != nb:
                return -1 if na < nb else 1
        elif a_num:
            return -1
        elif b_num:
            return 1
        else:
            if ia != ib:
                return -1 if ia < ib else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


@total_ordering
@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> SemVer:
        m = _SEMVER_RE.match(value)
        if not m:
            raise InvalidSemverError(value)
        pre = tuple(m.group("prerelease").split(".")) if m.group("prerelease") else ()
        return cls(int(m.group("major")), int(m.group("minor")), int(m.group("patch")), pre)

    def _key(self) -> tuple:
        has_pre = len(self.prerelease) > 0
        return (self.major, self.minor, self.patch, not has_pre, self.prerelease)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key() == other._key()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        s = (self.major, self.minor, self.patch)
        o = (other.major, other.minor, other.patch)
        if s != o:
            return s < o
        if not self.prerelease and not other.prerelease:
            return False
        if not self.prerelease:
            return False
        if not other.prerelease:
            return True
        return _compare_prerelease(self.prerelease, other.prerelease) < 0

    def __hash__(self) -> int:
        return hash(self._key())


def parse(value: str) -> SemVer | None:
    """Parse, returning None on invalid input."""
    try:
        return SemVer.parse(value)
    except InvalidSemverError:
        return None
