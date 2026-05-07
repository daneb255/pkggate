"""Abstract threat intel interface and shared types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Verdict:
    """Result of an intel lookup."""

    malicious: bool
    reason: str
    advisory_id: str | None = None


CLEAN = Verdict(malicious=False, reason="clean")
UNKNOWN = Verdict(malicious=False, reason="unknown")


class IntelSource(Protocol):
    """Protocol every threat intel backend must implement."""

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict: ...

    async def close(self) -> None: ...
