# Contributing

Contributions are explicitly welcome. pkggate is built for the community — small businesses, OSS maintainers, indie devs, and security teams who want supply-chain protection without an enterprise budget.

---

## Ways to contribute

- **Try it in your stack** and open issues for anything that breaks or surprises you.
- **Add ecosystem adapters** — Cargo, Maven, RubyGems, Go modules (plugin point already exists at `src/pkggate/proxy/`).
- **Improve the policy engine** — new rules, better defaults, clearer error messages.
- **Documentation and examples** — deployment guides for Kubernetes, Nomad, `systemd`.
- **Threat-intel integrations** beyond OSV.dev.

---

## Getting started

1. Fork the repository and create a feature branch.
2. Install the development dependencies:

    ```bash
    pip install -e ".[dev]"
    ```

3. Run the test suite:

    ```bash
    pytest tests/ -v
    ```

4. Run linting and type checks:

    ```bash
    ruff check src tests
    mypy src --ignore-missing-imports
    ```

5. Open a pull request describing the change and its motivation.

---

## Commit style

Follow [Conventional Commits](https://www.conventionalcommits.org/) where possible:

```
feat: add Cargo proxy adapter
fix: handle missing repository URL field gracefully
docs: add deployment guide for Kubernetes
```

---

## Code of Conduct

Participation in this project is governed by the [Contributor Covenant Code of Conduct](https://github.com/daneb255/pkggate/blob/main/CODE_OF_CONDUCT.md). By participating, you agree to uphold its terms.

---

## Where to start

If you're unsure where to begin, open a discussion or an issue tagged `question` — we'll help you find a good first task.
