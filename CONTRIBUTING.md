# Contributing to pkggate

Thank you for your interest in contributing to pkggate! This guide will help you get started with the development workflow and our CI/CD pipeline.

## Development Setup

### Prerequisites
- Python 3.11 or 3.12
- Git

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/daneb255/pkggate.git
cd pkggate
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install in development mode with all dependencies:
```bash
pip install -e ".[dev]"
```

## Code Quality

### Running Linting

Check code style with Ruff:
```bash
ruff check src tests
ruff format --check src tests
```

Auto-fix formatting issues:
```bash
ruff format src tests
```

### Type Checking

Run MyPy for type safety:
```bash
mypy src --ignore-missing-imports
```

### Testing

Run the test suite:
```bash
pytest tests/ -v
```

With coverage report:
```bash
pytest tests/ -v --cov=src --cov-report=html
```

## Security Checks

### Local Security Scanning

Check for Python security issues:
```bash
bandit -r src/
```

Check dependencies for vulnerabilities:
```bash
safety check
```

## Docker Development

### Build Docker image locally
```bash
docker build -t pkggate:latest .
```

### Run container
```bash
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  pkggate:latest
```

## CI/CD Pipeline

Our GitHub Actions workflows automatically run on:

1. **CI Workflow** (`ci.yml`)
   - Triggers: Push to `main`, Pull Requests to `main`
   - Runs: Linting (Ruff), Type checking (MyPy), Unit tests (Pytest)
   - Python versions: 3.11, 3.12

2. **Security Workflow** (`security.yml`)
   - Triggers: Push to `main`, Pull Requests, Weekly schedule (Monday 2:00 AM UTC)
   - Runs: Bandit (Python Security), Safety (Dependency audit)
   - Reports: Artifacts available in workflow run

3. **Docker Build & SBOM** (`docker.yml`)
   - Triggers: Push to `main`, Git tags (v*), PRs touching Dockerfile/src/config
   - Runs: Docker build → Trivy scan → push to GHCR; on tags also generates SBOM
   - Outputs: Docker image (ghcr.io), SBOM (CycloneDX JSON), Trivy SARIF results

4. **Dependabot** (`dependabot.yml`)
   - Automatically creates PRs for dependency updates
   - Runs weekly for pip, GitHub Actions, and Docker

## Pull Request Workflow

1. Create a feature branch:
```bash
git checkout -b feature/my-feature
```

2. Make your changes and commit with conventional commits:
```bash
git commit -m "feat: add new feature" 
git commit -m "fix: resolve issue"
git commit -m "docs: update documentation"
```

3. Push to your fork and create a PR:
```bash
git push origin feature/my-feature
```

4. Wait for CI checks to pass. The PR will be blocked if:
   - Ruff linting or formatting fails
   - MyPy type checking fails
   - Any test fails

5. Request review and address feedback

6. Once approved and all checks pass, your PR will be merged

## Release Process

1. Update version in `pyproject.toml`
2. Create a git tag: `git tag v0.2.0`
3. Push tag: `git push origin v0.2.0`
4. Docker image builds automatically and pushes to GitHub Container Registry
5. SBOM files are attached to the release

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Security vulnerabilities: See `SECURITY.md` for private reporting process

## Questions?

- Check existing issues and discussions
- Read the main `README.md` for project overview
- Consult the `CODE_OF_CONDUCT.md`
