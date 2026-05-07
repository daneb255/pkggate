"""Entry point for pkggate CLI."""

import asyncio
import logging
import sys

from pkggate.app import run
from pkggate.config import Settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def main() -> None:
    """Start pkggate server."""
    try:
        settings = Settings()
        asyncio.run(run(settings))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:
        logging.exception("Fatal error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
