from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import queue
import sqlite3
import threading
import zipfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp

from . import CLEAN, Verdict

log = logging.getLogger(__name__)
DEFAULT_NPM_BUNDLE = "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip"
DEFAULT_PYPI_BUNDLE = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
_SCHEMA_VERSION = "3"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS mal_exact (
    ecosystem TEXT NOT NULL,
    package   TEXT NOT NULL,
    version   TEXT NOT NULL,
    advisory  TEXT NOT NULL,
    PRIMARY KEY (ecosystem, package, version, advisory)
);
CREATE INDEX IF NOT EXISTS idx_mal_exact_pkg ON mal_exact(ecosystem, package);

CREATE TABLE IF NOT EXISTS mal_range (
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    introduced    TEXT,
    fixed         TEXT,
    last_affected TEXT,
    advisory      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mal_range_pkg ON mal_range(ecosystem, package);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS ecosystem_refresh (
    ecosystem          TEXT PRIMARY KEY,
    last_refresh_time  TEXT,
    last_advisory_id   TEXT,
    refresh_count      INTEGER DEFAULT 0
);
"""


class OsvMirror:
    """Local SQLite-backed OSV mirror for MAL advisories (npm, PyPI, and extensible)."""

    def __init__(
        self,
        db_path: Path,
        bundles: dict[str, str] | None = None,
        refresh_interval_seconds: int = 3600,
        pool_size: int = 4,
    ) -> None:
        self._bundles = dict(
            bundles
            if bundles is not None
            else {"npm": DEFAULT_NPM_BUNDLE, "PyPI": DEFAULT_PYPI_BUNDLE}
        )
        self._db_path = db_path
        self._refresh = refresh_interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._pool: queue.Queue[sqlite3.Connection] = queue.Queue(maxsize=pool_size)
        self._writer_lock = threading.Lock()
        self._writer: sqlite3.Connection | None = None
        self._closed = False
        self._init_schema(pool_size)

    @property
    def ecosystems(self) -> set[str]:
        return set(self._bundles.keys())

    def _init_schema(self, pool_size: int) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        boot = sqlite3.connect(self._db_path)
        try:
            boot.execute("PRAGMA journal_mode=WAL")
            boot.execute("PRAGMA synchronous=NORMAL")
            self._maybe_wipe_for_schema_change(boot)
            boot.executescript(_SCHEMA)
            boot.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (_SCHEMA_VERSION,),
            )
            boot.commit()
        finally:
            boot.close()
        for _ in range(pool_size):
            self._pool.put(self._open_reader())
        self._writer = self._open_writer()

    def _maybe_wipe_for_schema_change(self, conn: sqlite3.Connection) -> None:
        """Drop tables when the on-disk schema predates this version.

        The mirror is fully regenerable from the OSV bundle, so a wipe is
        cheap and avoids serving from a stale layout (e.g. the v1 schema
        had no ecosystem column).
        """
        try:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        except sqlite3.OperationalError:
            row = None
        current = row[0] if row else None
        if current == _SCHEMA_VERSION:
            return None
        else:
            if current is not None:
                log.info(
                    "mirror schema %s != expected %s — wiping for rebuild", current, _SCHEMA_VERSION
                )
            for table in ["mal_exact", "mal_range"]:
                conn.execute(f"DROP TABLE IF EXISTS {table}")

    def _open_reader(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        conn.execute("PRAGMA query_only=ON")
        return conn

    def _open_writer(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=False, timeout=30.0)

    @contextlib.contextmanager
    def _borrow(self) -> Iterator[sqlite3.Connection]:
        conn = self._pool.get()
        try:
            yield conn
        finally:
            self._pool.put(conn)

    async def start(self) -> None:
        """Start the background refresh task. Does an initial refresh first."""
        await self.refresh()
        self._task = asyncio.create_task(self._loop(), name="osv-mirror-refresh")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._close_pool()

    def _close_pool(self) -> None:
        if self._closed:
            return
        self._closed = True
        while True:
            try:
                conn = self._pool.get_nowait()
            except queue.Empty:
                break
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        if self._writer is not None:
            with contextlib.suppress(sqlite3.Error):
                self._writer.close()
            self._writer = None

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._refresh)
            except TimeoutError:
                pass
            if self._stop.is_set():
                return
            try:
                await self.refresh()
            except Exception as exc:
                log.error("mirror refresh failed: %s", exc)

    async def refresh(self) -> int:
        """Refresh every configured ecosystem from the full OSV bundle.

        Failures in one bundle do not invalidate the others.
        Returns the total number of MAL advisories loaded across ecosystems.
        Raises ``RuntimeError`` only if every configured bundle fails on the
        very first refresh (so callers can fall back to live-only mode).
        """
        total = 0
        succeeded = 0
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as s:
            for ecosystem, url in self._bundles.items():
                try:
                    log.info("refreshing OSV mirror %s (full bundle)", ecosystem)
                    advisories = await self._refresh_full(s, url, ecosystem)
                    await asyncio.to_thread(self._update_ecosystem, ecosystem, advisories)
                    log.info(
                        "OSV mirror refreshed %s: %d MAL advisories", ecosystem, len(advisories)
                    )
                    total += len(advisories)
                    succeeded += 1
                except Exception as exc:
                    log.error("mirror refresh failed for %s: %s", ecosystem, exc)

        if succeeded == 0:
            raise RuntimeError("all mirror bundles failed to refresh")
        return total

    async def _refresh_full(
        self, session: aiohttp.ClientSession, url: str, ecosystem: str
    ) -> list[dict[str, Any]]:
        """Download and parse the full OSV bundle."""
        async with session.get(url) as resp:
            resp.raise_for_status()
            blob = await resp.read()
        return list(_iter_mal_records(blob))

    def _get_last_refresh_time(self, ecosystem: str) -> str | None:
        """Get the timestamp of the last refresh for an ecosystem."""
        with self._borrow() as conn:
            row = conn.execute(
                "SELECT last_refresh_time FROM ecosystem_refresh WHERE ecosystem = ?",
                (ecosystem,),
            ).fetchone()
        return row[0] if row else None

    def _update_ecosystem(self, ecosystem: str, advisories: list[dict[str, Any]]) -> None:
        """Update or replace advisories for an ecosystem."""
        with self._writer_lock:
            conn = self._writer
            if conn is None:
                raise RuntimeError("mirror is closed")
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Check if this is first refresh
                existing = conn.execute(
                    "SELECT COUNT(*) FROM mal_exact WHERE ecosystem = ?", (ecosystem,)
                ).fetchone()

                if existing and existing[0] > 0:
                    # Incremental: merge with existing data
                    self._insert_advisories(conn, ecosystem, advisories)
                else:
                    # First refresh: replace all
                    conn.execute("DELETE FROM mal_exact WHERE ecosystem = ?", (ecosystem,))
                    conn.execute("DELETE FROM mal_range WHERE ecosystem = ?", (ecosystem,))
                    self._insert_advisories(conn, ecosystem, advisories)

                # Update refresh metadata
                now = datetime.now(UTC).isoformat()
                sql = (
                    "INSERT OR REPLACE INTO ecosystem_refresh"
                    "(ecosystem, last_refresh_time, refresh_count) "
                    "SELECT ?, ?, COALESCE("
                    "(SELECT refresh_count FROM ecosystem_refresh "
                    "WHERE ecosystem = ?), 0) + 1"
                )
                conn.execute(sql, (ecosystem, now, ecosystem))
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def _replace(self, ecosystem: str, advisories: Iterable[dict[str, Any]]) -> None:
        """Legacy method: replace all advisories for an ecosystem (full refresh)."""
        with self._writer_lock:
            conn = self._writer
            if conn is None:
                raise RuntimeError("mirror is closed")
            else:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute("DELETE FROM mal_exact WHERE ecosystem = ?", (ecosystem,))
                    conn.execute("DELETE FROM mal_range WHERE ecosystem = ?", (ecosystem,))
                    self._insert_advisories(conn, ecosystem, advisories)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def _insert_advisories(
        self, conn: sqlite3.Connection, ecosystem: str, advisories: Iterable[dict[str, Any]]
    ) -> None:
        for adv in advisories:
            adv_id = adv["id"]
            for affected in adv.get("affected") or []:
                pkg_info = affected.get("package") or {}
                pkg = pkg_info.get("name")
                if not pkg or pkg_info.get("ecosystem") != ecosystem:
                    continue
                else:
                    for v in affected.get("versions") or []:
                        conn.execute(
                            "INSERT OR IGNORE INTO mal_exact"
                            "(ecosystem, package, version, advisory) VALUES (?, ?, ?, ?)",
                            (ecosystem, pkg, v, adv_id),
                        )
                    for rng in affected.get("ranges") or []:
                        if rng.get("type") not in ["SEMVER", "ECOSYSTEM"]:
                            continue
                        else:
                            introduced = None
                            fixed = None
                            last_affected = None
                            for ev in rng.get("events") or []:
                                if "introduced" in ev:
                                    introduced = ev["introduced"]
                                else:
                                    if "fixed" in ev:
                                        fixed = ev["fixed"]
                                    else:
                                        if "last_affected" in ev:
                                            last_affected = ev["last_affected"]
                            if introduced is None and fixed is None and (last_affected is None):
                                continue
                            conn.execute(
                                "INSERT INTO mal_range"
                                "(ecosystem, package, introduced, fixed, last_affected, advisory)"
                                " VALUES (?, ?, ?, ?, ?, ?)",
                                (ecosystem, pkg, introduced, fixed, last_affected, adv_id),
                            )

    async def check(self, ecosystem: str, name: str, version: str) -> Verdict:
        return await asyncio.to_thread(self._check_sync, ecosystem, name, version)

    def _check_sync(self, ecosystem: str, name: str, version: str) -> Verdict:
        with self._borrow() as conn:
            row = conn.execute(
                "SELECT advisory FROM mal_exact"
                " WHERE ecosystem = ? AND package = ? AND version = ? LIMIT 1",
                (ecosystem, name, version),
            ).fetchone()
            if row:
                return Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id=row[0])
            else:
                ranges = conn.execute(
                    "SELECT introduced, fixed, last_affected, advisory"
                    " FROM mal_range WHERE ecosystem = ? AND package = ?",
                    (ecosystem, name),
                ).fetchall()
        for introduced, fixed, last_affected, advisory in ranges:
            if _version_in_range(version, introduced, fixed, last_affected):
                return Verdict(
                    malicious=True, reason="osv_malicious_advisory", advisory_id=advisory
                )
        return CLEAN


def _iter_mal_records(blob: bytes) -> Iterable[dict[str, Any]]:
    """Yield all ``MAL-*`` advisories from the OSV ecosystem zip bundle."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            if "/MAL-" not in info.filename and not info.filename.startswith("MAL-"):
                continue
            try:
                with zf.open(info) as fh:
                    record = json.load(fh)
            except json.JSONDecodeError:
                continue
            if not record.get("id", "").startswith("MAL-"):
                continue
            yield record


def _version_in_range(
    version: str, introduced: str | None, fixed: str | None, last_affected: str | None
) -> bool:
    """Check whether ``version`` falls within a SEMVER range.

    Uses a semver-2.0-conformant comparator so prerelease identifiers like
    ``beta.11`` vs ``beta.2`` order correctly (PEP 440 / packaging.Version
    gets these wrong, which would let malicious prerelease versions slip
    past the blocklist).
    """
    from ._semver import parse

    v = parse(version)
    if v is None:
        return False
    else:
        if introduced and introduced != "0":
            lo = parse(introduced)
            if lo is None or v < lo:
                return False
        if fixed:
            hi = parse(fixed)
            if hi is None or v >= hi:
                return False
        if last_affected:
            la = parse(last_affected)
            if la is None or v > la:
                return False
        return True
