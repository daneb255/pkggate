# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-05-09

### Added

- End-to-end load tests (`tests/test_e2e.py`) — 13 tests that spin up the full
  pkggate application (`build_app()`) alongside real fake upstream servers for npm
  and PyPI, then fire `CONCURRENCY=50` simultaneous requests to verify correctness
  under load with no internal proxy mocking
  - `TestNpmLoadE2E` (6 tests): concurrent metadata filtering, tarball pass-through,
    malicious tarball gate (upstream never contacted), mixed clean/malicious
    in-flight requests with no decision cross-contamination, scoped package handling
  - `TestPyPiLoadE2E` (5 tests): concurrent Simple API index filtering (PEP 691),
    malicious file stripping, file gate with SHA-256 integrity verification under
    load, mixed clean/malicious index requests simultaneously
  - `TestMixedLoadE2E` (2 tests): npm and PyPI traffic interleaved with no
    interference between ecosystems; health endpoint stays responsive under load
  - Stack helper (`_build_stack`) pre-allocates the pkggate port via `unused_port()`
    so `pypi_public_base_url` is known before startup, enabling correct URL
    rewriting through the proxy without any post-startup patching

---

## [0.1.3] - 2026-05-09

### Added

- CycloneDX SBOM generation for the PyPI package in the release workflow
  - Built wheel is installed into an isolated venv to capture runtime dependencies only (excludes build/CI tooling)
  - `cyclonedx-py environment` produces `sbom.cdx.json` in CycloneDX JSON format
  - SBOM is uploaded as a build artifact and attached to the GitHub Release with the label `CycloneDX SBOM (PyPI package)`
- GitHub Release now uploads wheel, sdist, and SBOM explicitly (replaces `dist/*` glob) to prevent the SBOM from being pushed to PyPI

---

## [0.1.2] - 2026-05-09

### Added

- Test suite for `app.py` — previously the core application factory had no coverage
  - `TestHealthEndpoint`: verifies `GET /-/pkggate/health` returns `{"status": "ok"}` with correct content type
  - `TestBuildIntel`: covers all intel-source construction paths (mirror on/off, live fallback, mirror start failure with graceful fallback and `stop()` call)
  - `TestBuildApp`: verifies app keys (`settings`, `policy`, `audit`), health route registration, and startup/cleanup hook wiring
  - `TestStartupLifecycle`: confirms `NpmProxy` always starts, `PyPiProxy` only when `pypi_enabled=True`, and health endpoint is reachable post-startup
  - `TestCleanupLifecycle`: confirms `shutdown()` is called on both proxies and cleanup is safe when PyPI is disabled

---

## [0.1.0] - 2026-05-07

**Status:** Early Preview Release

### Added - Core Features

#### Registry Proxy

- **npm registry proxy** with transparent threat detection
- **PyPI Simple API support** (PEP 691 compliant)
- Upstream registry failover support
- Request/response filtering and rewriting

#### Threat Intelligence

- **Local OSV mirror** for offline vulnerability lookups (SQLite-based)
- **Composite Intel source** combining mirror + live API
- Configurable refresh intervals (default: hourly)
- Live API fallback for packages published after mirror sync
- Ecosystem partitioning (npm, PyPI with extensible design)

#### Policy Engine

- Pluggable rule-based policy evaluation framework
- **block_malicious** — Block OSV MAL-* advisories
- **min_package_age_days** — Typosquat mitigation (configurable per ecosystem)
- **require_repository_url** — Reject packages without repo link
- **deny_lifecycle_scripts** — Block postinstall/preinstall scripts
- **allowlist/denylist** — Explicit overrides (name or `name@version`, `*` wildcard supported)
- **fail_closed** — Deny on threat intel unavailability

#### Audit & Compliance

- JSON Lines audit logging (`audit.log`)
- Per-decision audit entries with:
  - Timestamp, action (allow/block), package name/version
  - Triggered rule, advisory ID, source
- SIEM-ready format (integrates with any log aggregator)

#### DevOps & Deployment

- **Docker multi-stage build** for minimal runtime images
- **Non-root container user** (pkggate UID 1000)
- Environment variable configuration (pydantic-settings)
- Health check endpoint (`GET /-/pkggate/health`)
- `docker-compose.yml` for single-command deployment

### Added - Tooling & CI/CD

#### GitHub Actions Workflows

- **CI Pipeline** (`ci.yml`)
  - Matrix testing (Python 3.11, 3.12)
  - Ruff linting & formatting checks
  - MyPy type checking
  - Pytest unit tests with coverage
  - Codecov integration

- **Security Scanning** (`security.yml`)
  - Bandit for Python code security
  - Safety for dependency vulnerabilities
  - Weekly scheduled runs
  - PR comment summaries

- **Docker Build & SBOM** (`docker.yml`)
  - Multi-arch Docker image builds (linux/amd64, linux/arm64)
  - Trivy vulnerability scanning (SARIF output)
  - CycloneDX SBOM generation (dependencies)
  - Syft SBOM generation (container layers)
  - GitHub Container Registry push on tags

#### Dependency Management

- **Dependabot configuration** for automated PRs:
  - Python dependencies (weekly)
  - GitHub Actions (weekly)
  - Docker base images (weekly)

#### Development Tools

- **Pre-commit hooks** (Ruff, MyPy, Bandit, trailing whitespace, YAML validation)
- **Makefile** with 15+ convenience commands
- **Development documentation** (CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md)

### Configuration

#### pyproject.toml

- Modern PEP 621 project configuration
- Setuptools build backend with wheel support
- Development dependencies (pytest, ruff, mypy, bandit, safety, cyclonedx-bom)
- Tool configurations:
  - Ruff: line length 100, Python 3.11 target
  - MyPy: strict_optional, warn_return_any
  - Pytest: asyncio mode auto, tests/ discovery

#### config/policy.yaml

- YAML-based policy configuration
- Documented with inline examples
- Per-ecosystem rule overrides
- Allowlist/denylist support

#### Docker & Environment

- Multi-stage Dockerfile (builder + runtime)
- docker-compose.yml with volume mounts for config/logs
- `.env.example` with all configurable variables

### Documentation

#### Core Documentation

- **README.md** (200+ lines)
  - Project motivation & feature overview
  - Architecture diagram
  - Quick start (Docker, npm, pip setup)
  - Configuration reference
  - PyPI support details
  - Contributing guidelines

- **CONTRIBUTING.md** (160+ lines)
  - Development setup (venv, pip install)
  - Code quality tools (Ruff, MyPy, Pytest)
  - Security scanning (Bandit, Safety)
  - Docker development workflow
  - CI/CD pipeline explanation
  - Pull request workflow
  - Release process

- **SECURITY.md**
  - Vulnerability reporting process
  - Security considerations for deployment
  - Known limitations
  - Security roadmap

- **CODE_OF_CONDUCT.md**
  - Contributor Covenant v2.0
  - Standards, enforcement, reporting

- **.github/README.md**
  - Workflow documentation
  - Local development setup
  - Deployment guide
  - Troubleshooting

### Dependencies

#### Core Dependencies

- `aiohttp>=3.9` — Async HTTP proxy implementation
- `pydantic>=2.5` — Data validation (policy, settings)
- `pydantic-settings>=2.1` — Environment configuration
- `pyyaml>=6.0` — Policy file parsing
- `structlog>=24.1` — Structured logging
- `cachetools>=5.3` — Thread-safe caching for intel
- `packaging>=23.0` — Version parsing for age calculations

#### Development Dependencies

- `pytest>=8.0` — Unit testing framework
- `pytest-asyncio>=0.23` — Async test support
- `pytest-cov>=5.0` — Coverage reporting
- `aioresponses>=0.7` — Mock HTTP responses
- `ruff>=0.3` — Fast Python linter & formatter
- `mypy>=1.8` — Static type checking
- `bandit>=1.7` — Security static analysis
- `safety>=2.3` — Dependency vulnerability audit
- `cyclonedx-bom>=4.0` — SBOM generation

### Known Limitations

1. **No Authentication**
   - All clients have equal access
   - Deploy behind reverse proxy with auth (nginx, HAProxy)
   - Future: API key support planned

2. **No Native TLS**
   - Unencrypted by default
   - Use reverse proxy with mTLS for security
   - Future: Native TLS planned

3. **Limited PyPI Support**
   - OSV mirror primarily focused on npm
   - For PyPI: enable `PKGGATE_LIVE_FALLBACK_ENABLED=true`
   - Future: Full PyPI mirror planned

4. **Single Node Only**
   - No clustering/high-availability
   - SQLite database not suitable for multi-instance
   - Future: Distributed architecture planned

5. **No UI**
   - Audit log accessible only via logs
   - Future: Admin UI with visualization planned

---

## Roadmap

### [0.2.0] - Q3 2026

#### Ecosystem Expansion
- [ ] Cargo (Rust) adapter
- [ ] Maven (Java) adapter  
- [ ] Extensible adapter framework (plugin system)

#### Core Improvements
- [ ] Authentication layer (API keys, RBAC)
- [ ] Metrics/observability (Prometheus, OpenTelemetry)
- [ ] Admin UI for audit log inspection
- [ ] Helm chart for Kubernetes

#### Distribution
- [ ] Pre-built container images on ghcr.io
- [ ] Published to PyPI (installable via `pip install pkggate`)
- [ ] Systemd service unit file examples

### [0.3.0] - Q4 2026

#### Additional Ecosystems
- [ ] RubyGems support
- [ ] Go modules support
- [ ] Support for 2-3 more package managers

#### Advanced Features
- [ ] Additional threat-intel integrations (beyond OSV.dev)
- [ ] High-availability clustering
- [ ] Database provider abstraction (PostgreSQL, etc.)
- [ ] Distributed tracing support

#### Security Hardening
- [ ] Audit log encryption at rest
- [ ] TLS/HTTPS first-class support
- [ ] Threat model documentation
- [ ] Security audit by third party

### Future Considerations

- **Threat Intelligence**: Integration with Snyk, Sonatype, GitHub Advisories
- **AI/ML**: Anomaly detection for package installations
- **Enterprise**: Multi-tenant support, role-based access
- **Standards**: SLSA provenance, in-toto attestations

---

## Version History Notes

### v0.1.0 (This Release)
- **First public release** after internal development
- Early preview status — APIs subject to change
- Recommended for small teams, not production systems yet
- Feedback welcome: issues, discussions, PRs

---

## Breaking Changes

None yet — v0.1.0 is the initial release.

Future versions may change:
- Configuration file format (`config/policy.yaml`)
- Audit log schema (JSON structure)
- Environment variable names
- API endpoints

---

## Deprecated Features

None — this is the initial release.

---

## Security Advisories

None identified in v0.1.0.

If you discover a vulnerability:
- **DO NOT** file a public issue
- Email maintainer at `d@bitzer.dev` (see SECURITY.md)

---

## How to Report Issues

1. **Bug Reports**: [GitHub Issues](https://github.com/daneb255/pkggate/issues)
2. **Security Vulnerabilities**: Email maintainer (see SECURITY.md)
3. **Questions/Discussions**: [GitHub Discussions](https://github.com/daneb255/pkggate/discussions)

---

## Links

- [README.md](README.md) — Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) — Developer guide
- [SECURITY.md](SECURITY.md) — Security policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community standards
- [Keep a Changelog](https://keepachangelog.com/) — Format specification
- [Semantic Versioning](https://semver.org/) — Versioning spec
- [OSV.dev](https://osv.dev/) — Threat intelligence source
