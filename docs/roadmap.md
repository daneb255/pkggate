# Roadmap

pkggate is an early-stage prototype. The core npm and PyPI proxy works end-to-end, but there is plenty left to build.

---

## Near-term

- **Hardened policy schema** — stricter validation, clearer error messages for misconfigured rules.
- **Admin UI** — a small web dashboard for browsing and filtering the audit log.
- **Pre-built container images** — automated multi-arch builds published to GHCR on each release.
- **Helm chart** — first-class Kubernetes deployment.

## Ecosystem expansion

The proxy layer is designed as a plugin point. Planned adapters:

| Ecosystem | Status |
|---|---|
| npm | Supported |
| PyPI | Supported |
| Cargo | Planned |
| Maven | Planned |
| RubyGems | Planned |
| Go modules | Planned |

## Threat intelligence

- **Additional intel sources** — integrate beyond OSV.dev (e.g., Socket, Snyk, GitHub Advisory Database).
- **GHSA / CVE enforcement** — optionally block packages with known vulnerabilities (not just malicious ones).
- **Custom feeds** — allow organizations to plug in their own advisory feeds.

## Deployment

- `systemd` unit file and deployment guide for bare-metal / VM installs.
- Nomad job spec.
- Guidance for air-gapped environments (custom OSV bundle mirrors).

---

!!! tip "Want to help?"
    The roadmap is community-driven. If a feature matters to you, open an issue or a PR — see [Contributing](contributing.md).
