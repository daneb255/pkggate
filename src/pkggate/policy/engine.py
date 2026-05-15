"""Policy engine: loads config and evaluates rules in order."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import rules
from .rules import Decision, EvalContext


@dataclass
class EcosystemPolicy:
    """Per-ecosystem rule overrides.

    Each field is Optional — ``None`` means "inherit from the global policy".
    Scalar fields replace the global value; list fields (allowlist/denylist)
    are *additive*: ecosystem entries are appended to the global list so that
    global bans are never accidentally bypassed.
    """

    block_malicious: bool | None = None
    min_package_age_days: int | None = None
    require_repository_url: bool | None = None
    deny_lifecycle_scripts: bool | None = None
    max_cvss_score: float | None = None
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)

    def apply_to(self, base: Policy) -> Policy:
        """Return a new Policy with these overrides merged in."""
        return dataclasses.replace(
            base,
            block_malicious=(
                self.block_malicious if self.block_malicious is not None else base.block_malicious
            ),
            min_package_age_days=(
                self.min_package_age_days
                if self.min_package_age_days is not None
                else base.min_package_age_days
            ),
            require_repository_url=(
                self.require_repository_url
                if self.require_repository_url is not None
                else base.require_repository_url
            ),
            deny_lifecycle_scripts=(
                self.deny_lifecycle_scripts
                if self.deny_lifecycle_scripts is not None
                else base.deny_lifecycle_scripts
            ),
            max_cvss_score=(
                self.max_cvss_score if self.max_cvss_score is not None else base.max_cvss_score
            ),
            allowlist=base.allowlist + self.allowlist,
            denylist=base.denylist + self.denylist,
            ecosystems={},  # do not recurse
        )


@dataclass
class Policy:
    block_malicious: bool = True
    min_package_age_days: int = 0
    require_repository_url: bool = False
    deny_lifecycle_scripts: bool = False
    max_cvss_score: float | None = None
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    fail_closed: bool = True
    intel_cache_ttl: int = 3600
    ecosystems: dict[str, EcosystemPolicy] = field(default_factory=dict)


def _parse_ecosystem_overrides(raw: object) -> dict[str, EcosystemPolicy]:
    if not isinstance(raw, dict):
        return {}
    known = EcosystemPolicy.__dataclass_fields__.keys()
    result: dict[str, EcosystemPolicy] = {}
    for eco, values in raw.items():
        if not isinstance(values, dict):
            continue
        clean = {k: v for k, v in values.items() if k in known}
        result[str(eco)] = EcosystemPolicy(**clean)
    return result


def load_policy(path: Path) -> Policy:
    if not path.exists():
        return Policy()
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    ecosystems = _parse_ecosystem_overrides(data.get("ecosystems"))
    # Filter to known scalar/list fields only; ecosystems handled separately.
    known = {k for k in Policy.__dataclass_fields__ if k != "ecosystems"}
    clean = {k: v for k, v in data.items() if k in known}
    return Policy(**clean, ecosystems=ecosystems)


class PolicyEngine:
    """Evaluates an EvalContext against a Policy.

    Order of evaluation (after ecosystem overrides are merged):
      1. denylist (hard block, cannot be bypassed)
      2. allowlist (short-circuits remaining rules)
      3. block_malicious (intel verdict)
      4. block_cvss_score (CVSS threshold from intel)
      5. min_package_age_days
      6. require_repository_url
      7. deny_lifecycle_scripts
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def replace_policy(self, policy: Policy) -> None:
        """Atomically replace the active policy for subsequent evaluations."""
        self._policy = policy

    def evaluate(self, ctx: EvalContext) -> Decision:
        p = self._policy
        eco = p.ecosystems.get(ctx.ecosystem)
        if eco is not None:
            p = eco.apply_to(p)

        if p.denylist:
            d = rules.rule_denylist(ctx, p.denylist)
            if d is not None:
                return d

        if p.allowlist:
            d = rules.rule_allowlist(ctx, p.allowlist)
            if d is not None:
                return d

        if p.block_malicious:
            d = rules.rule_block_malicious(ctx)
            if d is not None:
                return d

        if p.max_cvss_score is not None:
            d = rules.rule_block_cvss(ctx, p.max_cvss_score)
            if d is not None:
                return d

        if p.min_package_age_days > 0:
            d = rules.rule_min_package_age(ctx, p.min_package_age_days)
            if d is not None:
                return d

        if p.require_repository_url:
            d = rules.rule_require_repository_url(ctx)
            if d is not None:
                return d

        if p.deny_lifecycle_scripts:
            d = rules.rule_deny_lifecycle_scripts(ctx)
            if d is not None:
                return d

        return Decision.pass_()
