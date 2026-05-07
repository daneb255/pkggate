# GitHub Workflows for pkggate

This directory contains the CI/CD automation for the pkggate project.

## Workflows

### [`ci.yml`](workflows/ci.yml)
**Continuous Integration** — Runs on every push to `main` and pull requests.

- **Triggers:** Push to main, Pull Requests to main
- **Python versions:** 3.11, 3.12 (matrix testing)
- **Steps:**
  1. Lint with Ruff (check style)
  2. Format check with Ruff
  3. Type check with MyPy
  4. Run unit tests with Pytest
  5. Upload coverage to Codecov

**Branch protection:** This workflow must pass before merging to main.

---

### [`security.yml`](workflows/security.yml)
**Security Scanning** — Security checks for code and dependencies.

- **Triggers:** 
  - Push to main
  - Pull Requests to main
  - Weekly schedule (Monday 2:00 AM UTC)
- **Steps:**
  1. **Bandit** — Python security static analysis (PEP 8, CWE coverage)
  2. **Safety** — Dependency vulnerability scanning
  3. PR comment with results
  4. Artifact upload (reports available in workflow artifacts)

**Artifacts:** `bandit-report.json`, `safety-report.json`

---

### [`docker.yml`](docker.yml)
**Docker Build & SBOM** — Docker image building and security scanning.

- **Triggers:**
  - Git tags matching `v*` (e.g., `v0.1.0`)
  - Changes to Dockerfile, src/, config/, or pyproject.toml
- **Steps:**
  1. Build Docker image (multi-stage)
  2. **Trivy** — Scan image for vulnerabilities (SARIF output)
  3. **cyclonedx-bom** — Generate Python dependency SBOM
  4. **Syft** — Generate Docker image SBOM
  5. Upload to GitHub Container Registry (on tag release)
  6. Attach SBOM files to GitHub release

**Artifacts:** 
- `sbom.json` — Python dependencies (CycloneDX format)
- `image-sbom.json` — Docker image layers (CycloneDX format)
- `trivy-results.sarif` — Trivy vulnerability report

**Registry:** Docker images pushed to `ghcr.io/$(REPO_OWNER)/pkggate`

---

### [`.dependabot.yml`](dependabot.yml)
**Automated Dependency Updates** — Dependabot creates PRs for updates.

- **Update frequency:** Weekly (Monday 3 AM, 4 AM, 5 AM UTC)
- **Ecosystems:**
  - `pip` — Python dependencies
  - `github-actions` — Workflow actions
  - `docker` — Base image updates
- **PR limits:** 5 for pip, 3 for actions, 2 for docker
- **Labels:** `dependencies`, `python`, `github-actions`, `docker`

---

## Local Development

### Pre-commit Hooks

Set up pre-commit hooks to run checks before committing:

```bash
# Install pre-commit framework
pip install pre-commit

# Install hook scripts
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

Hooks configured in [`.pre-commit-config.yaml`](../.pre-commit-config.yaml):
- Ruff (linting & formatting)
- MyPy (type checking)
- Standard file checks (trailing whitespace, YAML validation)
- Bandit (security)

### Running Checks Locally

```bash
# Code quality
ruff check src tests
ruff format --check src tests

# Type checking
mypy src

# Security
bandit -r src/

# Testing
pytest tests/ -v --cov=src

# All at once
make test  # if using Makefile, or run manually
```

---

## Deployment

### Releasing a New Version

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create a git tag:
   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```
4. `docker-build.yml` workflow triggers automatically:
   - Builds Docker image
   - Scans for vulnerabilities
   - Generates SBOM
   - Pushes to GitHub Container Registry
   - Attaches artifacts to GitHub release

---

## Troubleshooting

### CI checks failing locally but passing in GitHub Actions

- Make sure Python version matches: `python --version` should be 3.11 or 3.12
- Clear caches: `rm -rf .pytest_cache .mypy_cache .ruff_cache`
- Run full setup: `pip install -e ".[dev]"`

### MyPy checks too strict

- MyPy is configured to be helpful but not strict by default
- See `pyproject.toml` `[tool.mypy]` section
- To skip specific lines: `# type: ignore`

### Docker image too large

- Multi-stage build already in place
- Check `Dockerfile` for base image optimization
- Consider using distroless images in future versions

---

## GitHub Secrets

The workflows use the following GitHub Secrets (optional, for full functionality):

- `GITHUB_TOKEN` — Automatically provided by GitHub Actions (for registry push)
- Custom registry credentials can be added for private registries

---

## See Also

- [README.md](../README.md) — Project overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Developer guidelines
- [SECURITY.md](../SECURITY.md) — Security policy
