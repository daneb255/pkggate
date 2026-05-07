"""aiohttp application wiring.

Default intel source is the local OSV mirror. When the mirror cannot be
initialised (network blocked, disk full, etc.) the app falls back to the
live OSV API, honouring the fail-closed policy setting.
"""

from __future__ import annotations

import asyncio
import logging

from aiohttp import web

from .audit import AuditLogger
from .config import Settings
from .intel import IntelSource
from .intel.composite import CompositeIntel
from .intel.mirror import OsvMirror
from .intel.osv import OsvIntel
from .policy import PolicyEngine, load_policy
from .proxy import NpmProxy
from .proxy.pypi import PyPiProxy

log = logging.getLogger(__name__)


async def _health(_: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def _build_intel(settings: Settings, fail_closed: bool) -> IntelSource:
    """Build the intel source according to settings."""
    live: OsvIntel | None = None
    if settings.live_fallback_enabled or not settings.mirror_enabled:
        live = OsvIntel(
            api_url=settings.osv_api,
            timeout=settings.intel_timeout_seconds,
            fail_closed=fail_closed,
        )

    if not settings.mirror_enabled:
        assert live is not None  # enforced by the branch above
        return live

    mirror = OsvMirror(
        db_path=settings.mirror_db,
        bundles={"npm": settings.osv_bundle_npm, "PyPI": settings.osv_bundle_pypi},
        refresh_interval_seconds=settings.mirror_refresh_seconds,
    )
    try:
        await mirror.start()
    except Exception as exc:
        log.warning("mirror initial refresh failed (%s) - continuing with live API only", exc)
        await mirror.stop()
        if live is None:
            live = OsvIntel(
                api_url=settings.osv_api,
                timeout=settings.intel_timeout_seconds,
                fail_closed=fail_closed,
            )
        return live

    return CompositeIntel(
        mirror=mirror,
        live=live,
        live_fallback_for_clean=settings.live_fallback_enabled,
    )


def build_app(settings: Settings) -> web.Application:
    policy = load_policy(settings.policy_file)
    engine = PolicyEngine(policy)
    audit = AuditLogger(settings.audit_log)

    app = web.Application()
    app["settings"] = settings
    app["policy"] = engine
    app["audit"] = audit
    app.router.add_get("/-/pkggate/health", _health)

    async def _on_startup(app: web.Application) -> None:
        s: Settings = app["settings"]
        intel = await _build_intel(s, fail_closed=policy.fail_closed)

        if s.pypi_enabled:
            pypi = PyPiProxy(
                upstream_simple=s.pypi_upstream_simple,
                upstream_files=s.pypi_upstream_files,
                intel=intel,
                policy=app["policy"],
                audit=app["audit"],
                public_base_url=s.pypi_public_base_url,
                upstream_timeout=s.upstream_timeout_seconds,
                verify_integrity=s.pypi_verify_integrity,
                tarball_max_buffer_bytes=s.pypi_max_buffer_bytes,
            )
            await pypi.startup()
            app["pypi"] = pypi
            pypi.register(app)

        npm = NpmProxy(
            upstream=s.upstream_npm,
            intel=intel,
            policy=app["policy"],
            audit=app["audit"],
            upstream_timeout=s.upstream_timeout_seconds,
        )
        await npm.startup()
        app["npm"] = npm
        # Register catch-all after PyPI routes so npm doesn't shadow /simple/.
        app.router.add_route("*", "/{path:.*}", npm.handle)
        log.info(
            "pkggate listening on %s:%d upstream_npm=%s pypi=%s mirror=%s live_fallback=%s",
            s.host,
            s.port,
            s.upstream_npm,
            s.pypi_enabled,
            s.mirror_enabled,
            s.live_fallback_enabled,
        )

    async def _on_cleanup(app: web.Application) -> None:
        pypi = app.get("pypi")
        if pypi is not None:
            await pypi.shutdown()
        npm = app.get("npm")
        if npm is not None:
            await npm.shutdown()

    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


async def run(settings: Settings) -> None:
    app = build_app(settings)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=settings.host, port=settings.port)
    await site.start()
    await asyncio.Event().wait()
