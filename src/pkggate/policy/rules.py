"""Individual policy rules.

Each rule inspects the context and returns a Decision. The engine aggregates
them in order; the first DENY wins.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..intel import Verdict


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule: str
    reason: str
    source: str | None = None

    @classmethod
    def deny(cls, rule: str, reason: str, source: str | None = None) -> Decision:
        return cls(allow=False, rule=rule, reason=reason, source=source)

    @classmethod
    def pass_(cls, rule: str = "default", reason: str = "no_rule_matched") -> Decision:
        return cls(allow=True, rule=rule, reason=reason)


@dataclass
class EvalContext:
    """Everything a rule might want to inspect."""

    name: str
    version: str
    ecosystem: str
    # May be None for tarball-only requests; populated when metadata is available.
    version_manifest: dict[str, Any] | None = None
    # Intel verdict from an external source (OSV etc.).
    intel: Verdict | None = None


# --- rule implementations ---------------------------------------------------


def rule_denylist(ctx: EvalContext, entries: list[str]) -> Decision | None:
    for entry in entries:
        if _matches(entry, ctx.name, ctx.version):
            return Decision.deny("denylist", f"explicit denylist entry: {entry}")
    return None


def rule_allowlist(ctx: EvalContext, entries: list[str]) -> Decision | None:
    """Allowlist short-circuits *to allow*, bypassing further rules."""
    for entry in entries:
        if _matches(entry, ctx.name, ctx.version):
            return Decision.pass_("allowlist", f"explicit allowlist entry: {entry}")
    return None


def rule_block_malicious(ctx: EvalContext) -> Decision | None:
    if ctx.intel and ctx.intel.malicious:
        return Decision.deny(
            "block_malicious",
            ctx.intel.reason,
            source=ctx.intel.advisory_id,
        )
    return None


def rule_block_cvss(ctx: EvalContext, max_score: float) -> Decision | None:
    if ctx.intel is None or ctx.intel.max_cvss is None:
        return None
    if ctx.intel.max_cvss >= max_score:
        return Decision.deny(
            "block_cvss_score",
            f"CVSS score {ctx.intel.max_cvss:.1f} meets or exceeds threshold {max_score:.1f}",
            source=ctx.intel.advisory_id,
        )
    return None


def rule_min_package_age(ctx: EvalContext, min_days: int) -> Decision | None:
    if min_days <= 0 or ctx.version_manifest is None:
        return None
    # npm manifests carry a top-level "time" map on the package doc, not on the
    # per-version manifest. The engine stitches this in before evaluation.
    published_at = ctx.version_manifest.get("_published_at")
    if not published_at:
        return None
    try:
        ts = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    age = datetime.now(UTC) - ts
    if age < timedelta(days=min_days):
        return Decision.deny(
            "min_package_age_days",
            f"version published {age.days}d ago, minimum is {min_days}d",
        )
    return None


def rule_deny_lifecycle_scripts(ctx: EvalContext) -> Decision | None:
    if ctx.version_manifest is None:
        return None
    scripts = ctx.version_manifest.get("scripts") or {}
    hooks = {"preinstall", "install", "postinstall"}
    hit = hooks & scripts.keys()
    if hit:
        return Decision.deny(
            "deny_lifecycle_scripts",
            f"declares lifecycle scripts: {sorted(hit)}",
        )
    return None


def rule_require_repository_url(ctx: EvalContext) -> Decision | None:
    if ctx.version_manifest is None:
        return None
    repo = ctx.version_manifest.get("repository")
    if isinstance(repo, dict):
        url = repo.get("url")
    else:
        url = repo
    if not url:
        return Decision.deny(
            "require_repository_url",
            "no repository URL declared in package manifest",
        )
    return None


# --- helpers ----------------------------------------------------------------


def _matches(entry: str, name: str, version: str) -> bool:
    """Match 'name' or 'name@version' entries. Version may be '*' to match any.

    Handles scoped npm packages: '@scope/pkg@1.0.0' uses find('@', 1) to skip
    the leading '@' and find the version separator.
    """
    at_idx = entry.find("@", 1)  # skip leading '@' for scoped packages
    if at_idx != -1:
        ename = entry[:at_idx]
        eversion = entry[at_idx + 1 :]
        return ename == name and (eversion == "*" or eversion == version)
    return entry == name
