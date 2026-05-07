"""Tests for configuration loading."""

from pathlib import Path

from pkggate.config import Settings


class TestSettingsDefaults:
    """Test Settings defaults."""

    def test_defaults(self) -> None:
        """Settings should have sensible defaults."""
        # Clear env to test defaults
        import os

        env_backup = {k: v for k, v in os.environ.items() if k.startswith("PKGGATE_")}
        for k in env_backup:
            del os.environ[k]

        try:
            s = Settings()
            assert s.host == "127.0.0.1"
            assert s.port == 8080
            assert s.upstream_npm == "https://registry.npmjs.org"
            assert s.mirror_enabled is True
            assert s.live_fallback_enabled is False
        finally:
            # Restore env
            for k, v in env_backup.items():
                os.environ[k] = v

    def test_env_override(self) -> None:
        """Environment variables should override defaults."""
        import os

        os.environ["PKGGATE_PORT"] = "9000"
        os.environ["PKGGATE_HOST"] = "0.0.0.0"

        try:
            s = Settings()
            assert s.port == 9000
            assert s.host == "0.0.0.0"
        finally:
            del os.environ["PKGGATE_PORT"]
            del os.environ["PKGGATE_HOST"]


class TestPathResolution:
    """Test path resolution in settings."""

    def test_policy_file_path(self) -> None:
        """Policy file path should be resolvable."""
        s = Settings()
        assert isinstance(s.policy_file, Path)
        assert s.policy_file.name == "policy.yaml"

    def test_audit_log_path(self) -> None:
        """Audit log path should be resolvable."""
        s = Settings()
        assert isinstance(s.audit_log, Path)
        assert s.audit_log.name == "audit.log"
