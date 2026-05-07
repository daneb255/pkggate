"""Tests for package utilities."""

from pkggate.utils import TarballRef, parse_metadata_path, parse_tarball_path


class TestTarballParsing:
    """Test tarball path parsing."""

    def test_parse_simple_tarball(self) -> None:
        """Parse simple tarball paths."""
        ref = parse_tarball_path("lodash/-/lodash-4.17.21.tgz")
        assert ref == TarballRef(name="lodash", version="4.17.21")

    def test_parse_scoped_tarball(self) -> None:
        """Parse scoped package tarballs."""
        ref = parse_tarball_path("@babel/core/-/core-7.24.0.tgz")
        assert ref == TarballRef(name="@babel/core", version="7.24.0")

    def test_invalid_tarball_path(self) -> None:
        """Invalid paths should return None."""
        assert parse_tarball_path("invalid") is None
        assert parse_tarball_path("lodash/missing") is None


class TestMetadataParsing:
    """Test metadata path parsing."""

    def test_parse_simple_name(self) -> None:
        """Parse simple package names."""
        name = parse_metadata_path("lodash")
        assert name == "lodash"

    def test_parse_scoped_name(self) -> None:
        """Parse scoped package names."""
        name = parse_metadata_path("@babel/core")
        assert name == "@babel/core"

    def test_invalid_metadata_path(self) -> None:
        """Invalid paths should return None."""
        assert parse_metadata_path("@invalid") is None
        assert parse_metadata_path("") is None
