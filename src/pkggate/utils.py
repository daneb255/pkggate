"""Path and name helpers for npm registry requests."""

from __future__ import annotations

import re
from typing import NamedTuple

# Tarball request:
#   <pkg>/-/<file>-<version>.tgz
#   @<scope>/<pkg>/-/<file>-<version>.tgz
# npm embeds the unscoped base name in the tarball filename even for scoped pkgs.
_TARBALL = re.compile(r"^(?P<name>@[^/]+/[^/]+|[^/@][^/]*)/-/[^/]+-(?P<version>\d[^/]*)\.tgz$")

# Metadata document request:
#   <pkg>
#   @<scope>/<pkg>
_METADATA = re.compile(r"^(?P<name>@[^/]+/[^/]+|[^/@][^/]*)$")


class TarballRef(NamedTuple):
    name: str
    version: str


def parse_tarball_path(path: str) -> TarballRef | None:
    path = path.lstrip("/")
    m = _TARBALL.match(path)
    if not m:
        return None
    return TarballRef(name=m.group("name"), version=m.group("version"))


def parse_metadata_path(path: str) -> str | None:
    path = path.lstrip("/").rstrip("/")
    m = _METADATA.match(path)
    if not m:
        return None
    return m.group("name")


def is_tarball_url(url_path: str) -> bool:
    return parse_tarball_path(url_path) is not None
