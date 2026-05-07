"""Tests for policy engine and rules."""

from datetime import UTC, datetime, timedelta

from pkggate.intel import CLEAN, Verdict
from pkggate.policy import Policy, PolicyEngine
from pkggate.policy.rules import EvalContext


def _ctx(**kwargs) -> EvalContext:
    """Create a test context with defaults."""
    defaults = dict(
        name="lodash",
        version="4.17.21",
        ecosystem="npm",
        intel=CLEAN,
    )
    defaults.update(kwargs)
    return EvalContext(**defaults)


class TestMalicious:
    """Test block_malicious rule."""

    def test_blocks_on_malicious_intel(self) -> None:
        """Malicious packages should be blocked."""
        v = Verdict(malicious=True, reason="osv_malicious_advisory", advisory_id="MAL-2024-1")
        engine = PolicyEngine(Policy(block_malicious=True))
        d = engine.evaluate(_ctx(intel=v))
        assert not d.allow
        assert d.rule == "block_malicious"
        assert d.source == "MAL-2024-1"

    def test_passes_on_clean(self) -> None:
        """Clean packages should pass."""
        engine = PolicyEngine(Policy(block_malicious=True))
        d = engine.evaluate(_ctx())
        assert d.allow


class TestPackageAge:
    """Test min_package_age_days rule."""

    def test_blocks_new_packages(self) -> None:
        """Packages younger than min_age should be blocked."""
        now = datetime.now(UTC)
        published = now - timedelta(days=2)

        manifest = {
            "_published_at": published.isoformat().replace("+00:00", "Z"),
        }

        engine = PolicyEngine(Policy(min_package_age_days=7))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert not d.allow
        assert d.rule == "min_package_age_days"

    def test_allows_old_packages(self) -> None:
        """Packages older than min_age should pass."""
        now = datetime.now(UTC)
        published = now - timedelta(days=30)

        manifest = {
            "_published_at": published.isoformat().replace("+00:00", "Z"),
        }

        engine = PolicyEngine(Policy(min_package_age_days=7))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert d.allow


class TestRepositoryUrl:
    """Test require_repository_url rule."""

    def test_blocks_without_repo(self) -> None:
        """Packages without repo URL should be blocked when required."""
        manifest = {"repository": None}
        engine = PolicyEngine(Policy(require_repository_url=True))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert not d.allow
        assert d.rule == "require_repository_url"

    def test_allows_with_repo(self) -> None:
        """Packages with repo URL should pass."""
        manifest = {"repository": "https://github.com/lodash/lodash"}
        engine = PolicyEngine(Policy(require_repository_url=True))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert d.allow


class TestLifecycleScripts:
    """Test deny_lifecycle_scripts rule."""

    def test_blocks_with_postinstall(self) -> None:
        """Packages with postinstall scripts should be blocked."""
        manifest = {"scripts": {"postinstall": "node install.js"}}
        engine = PolicyEngine(Policy(deny_lifecycle_scripts=True))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert not d.allow
        assert d.rule == "deny_lifecycle_scripts"

    def test_allows_without_scripts(self) -> None:
        """Packages without scripts should pass."""
        manifest = {"scripts": {"build": "tsc", "test": "jest"}}
        engine = PolicyEngine(Policy(deny_lifecycle_scripts=True))
        d = engine.evaluate(_ctx(version_manifest=manifest))
        assert d.allow


class TestLists:
    """Test allowlist/denylist rules."""

    def test_allowlist_short_circuits(self) -> None:
        """Allowlisted packages pass even if other rules would block."""
        v = Verdict(malicious=True, reason="test", advisory_id="MAL-2024-1")
        policy = Policy(
            block_malicious=True,
            allowlist=["lodash@*"],
        )
        engine = PolicyEngine(policy)
        d = engine.evaluate(_ctx(intel=v))
        assert d.allow
        assert d.rule == "allowlist"

    def test_denylist_blocks(self) -> None:
        """Denylisted packages are blocked."""
        policy = Policy(denylist=["evil-lib@*"])
        engine = PolicyEngine(policy)
        d = engine.evaluate(_ctx(name="evil-lib", version="1.0.0"))
        assert not d.allow
        assert d.rule == "denylist"


class TestOrdering:
    """Test rule evaluation order."""

    def test_allowlist_before_malicious(self) -> None:
        """Allowlist should be checked before malicious."""
        v = Verdict(malicious=True, reason="test", advisory_id="MAL-2024-1")
        policy = Policy(
            block_malicious=True,
            allowlist=["lodash@*"],
        )
        engine = PolicyEngine(policy)
        d = engine.evaluate(_ctx(intel=v))
        # Allowlist comes first, so should allow
        assert d.allow
        assert d.rule == "allowlist"

    def test_denylist_before_allowlist(self) -> None:
        """Denylist should override allowlist."""
        policy = Policy(
            allowlist=["evil-lib@*"],
            denylist=["evil-lib@*"],
        )
        engine = PolicyEngine(policy)
        d = engine.evaluate(_ctx(name="evil-lib", version="1.0.0"))
        # Denylist is checked first, so it wins over allowlist
        assert not d.allow
        assert d.rule == "denylist"


class TestScopedPackageMatching:
    """Test that scoped npm packages work in allow/deny lists."""

    def test_scoped_exact_version_denylist(self) -> None:
        policy = Policy(denylist=["@aws-sdk/client-s3@2.0.0"])
        engine = PolicyEngine(policy)
        assert not engine.evaluate(_ctx(name="@aws-sdk/client-s3", version="2.0.0")).allow
        assert engine.evaluate(_ctx(name="@aws-sdk/client-s3", version="2.0.1")).allow

    def test_scoped_wildcard_denylist(self) -> None:
        policy = Policy(denylist=["@aws-sdk/client-s3@*"])
        engine = PolicyEngine(policy)
        assert not engine.evaluate(_ctx(name="@aws-sdk/client-s3", version="2.0.0")).allow
        assert not engine.evaluate(_ctx(name="@aws-sdk/client-s3", version="99.0.0")).allow

    def test_scoped_name_only_denylist(self) -> None:
        policy = Policy(denylist=["@aws-sdk/client-s3"])
        engine = PolicyEngine(policy)
        assert not engine.evaluate(_ctx(name="@aws-sdk/client-s3", version="2.0.0")).allow

    def test_scoped_allowlist_overrides_malicious(self) -> None:
        v = Verdict(malicious=True, reason="test", advisory_id="MAL-1")
        policy = Policy(block_malicious=True, allowlist=["@scope/trusted@*"])
        engine = PolicyEngine(policy)
        assert engine.evaluate(_ctx(name="@scope/trusted", version="1.0.0", intel=v)).allow
