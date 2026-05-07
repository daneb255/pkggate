"""HTTP proxy handlers per ecosystem."""

from .npm import NpmProxy
from .pypi import PyPiProxy

__all__ = ["NpmProxy", "PyPiProxy"]
