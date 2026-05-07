"""Policy engine: loads config and evaluates rules in order."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import rules
from .rules import Decision, EvalContext


@dataclass
class Policy:
    block_malicious: bool = True
    min_package_age_days: int = 0
    require_repository_url: bool = False
    deny_lifecycle_scripts: bool = False
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    fail_closed: bool = True
    intel_cache_ttl: int = 3600


def load_policy(path: Path) -> Policy:
    if not path.exists():
        return Policy()
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    # Filter unknown keys to avoid TypeError on minor version drift.
    known = Policy.__dataclass_fields__.keys()
    clean = {k: v for k, v in data.items() if k in known}
    return Policy(**clean)


class PolicyEngine:
    """Evaluates an EvalContext against a Policy.

    Order of evaluation:
      1. denylist (hard block, cannot be bypassed)
      2. allowlist (short-circuits remaining rules)
      3. block_malicious (intel verdict)
      4. min_package_age_days
      5. require_repository_url
      6. deny_lifecycle_scripts
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, ctx: EvalContext) -> Decision:
        p = self._policy

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
