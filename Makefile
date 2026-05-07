.PHONY: help install install-dev lint format type-check test security docker clean

help:
	@echo "pkggate development commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install         Install production dependencies"
	@echo "  make install-dev     Install dev dependencies"
	@echo ""
	@echo "Code quality:"
	@echo "  make lint            Run Ruff linting checks"
	@echo "  make format          Auto-format code with Ruff"
	@echo "  make type-check      Run MyPy type checking"
	@echo "  make test            Run unit tests"
	@echo "  make test-cov        Run tests with coverage"
	@echo ""
	@echo "Security:"
	@echo "  make security        Run security scans (Bandit, Safety)"
	@echo "  make security-full   Run full security pipeline"
	@echo ""
	@echo "Docker:"
	@echo "  make docker          Build Docker image locally"
	@echo "  make docker-run      Build and run Docker container"
	@echo ""
	@echo "Development:"
	@echo "  make pre-commit      Install pre-commit hooks"
	@echo "  make dev             Full development setup (install-dev + pre-commit)"
	@echo "  make clean           Remove build artifacts"
	@echo "  make all             Run lint, type-check, test, security"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

lint:
	ruff check src tests

format:
	ruff format src tests

type-check:
	mypy src --ignore-missing-imports

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

security:
	bandit -r src/ && safety check

security-full: security
	docker build -t pkggate:local . && trivy image pkggate:local

docker:
	docker build -t pkggate:local .

docker-run: docker
	docker run -p 8080:8080 \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/audit.log:/app/audit.log \
		pkggate:local

pre-commit:
	pre-commit install
	pre-commit run --all-files

dev: install-dev pre-commit

all: lint type-check test security

clean:
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
