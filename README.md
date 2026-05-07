# pkggate — Open-Source Package Firewall for npm & PyPI

> **Block malicious packages before they reach `node_modules` or `site-packages`.**
> A lightweight, self-hosted supply-chain firewall for small and mid-sized teams — free, open-source, and built on public threat intelligence (OSV.dev).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Status: Early Preview](https://img.shields.io/badge/status-early--preview-orange.svg)](#project-status)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](#contributing)

**Keywords:** package firewall, supply chain security, npm proxy, pypi proxy, malicious package blocker, OSV mirror, dependency security, software supply chain, self-hosted security, open-source security tooling.

---

## Why pkggate?

Software supply-chain attacks against npm and PyPI keep growing — typosquats, account takeovers, and malicious post-install scripts are now everyday threats. Commercial package firewalls exist, but their pricing often locks out small teams, indie developers, and OSS maintainers.

**pkggate is a free, self-hosted alternative** designed for organizations that need supply-chain protection without enterprise contracts:

- **Zero cost, full control** — runs in your own infrastructure, no vendor lock-in.
- **Drop-in proxy** — point `npm` and `pip` at pkggate; everything else stays the same.
- **Offline-capable threat intel** — local OSV mirror means lookups don't leak which packages you install.
- **Policy-driven** — block by advisory, package age, missing repository links, lifecycle scripts, or explicit allow/deny lists.
- **Auditable** — every decision lands in a JSON Lines audit log.

Inspired by:
- [Socket Firewall (sfw)](https://github.com/SocketDev/sfw-free)
- [Datadog supply-chain-firewall](https://github.com/DataDog/supply-chain-firewall)
- [OSSF Malicious Packages](https://github.com/ossf/malicious-packages)

---

## How it works

pkggate acts as a registry to your package manager. Every request is checked against a threat-intel source (OSV.dev) and a policy engine. Hits are blocked with HTTP 403 and recorded in the audit log.

```
+---------+       +--------+        +---------------------+
|  npm /  | --->  | pkggate  |  --->  |  npm / PyPI         |
|  pip    |       |        |        |  upstream registry  |
+---------+       |   +----v----+   +---------------------+
                  |   | OSV API |
                  |   +---------+
                  |   +---------+
                  |   | Policy  |
                  +---+---------+
```

Two checkpoints (npm):

1. **Metadata response** (`GET /<pkg>`) — versions with a `MAL-*` advisory are stripped from the `versions` map so the client never tries to resolve them.
2. **Tarball request** (`GET /<pkg>/-/<pkg>-<ver>.tgz`) — final check before the file is delivered.

---

## Quick start

### Run with Docker

```bash
docker compose up
```

### Point npm at pkggate

```bash
echo "registry=http://localhost:8080/" > ~/.npmrc

# Clear the cache once, otherwise npm bypasses the proxy
npm cache clean --force

npm install express
```

### Point pip at pkggate

```bash
pip config set global.index-url http://localhost:8080/simple/
pip install requests
```

That's it — installs now flow through pkggate and malicious versions are blocked transparently.

---

## Threat intelligence

By default pkggate runs a **local OSV mirror** for both supported ecosystems (npm and PyPI). At startup it downloads each ecosystem's OSV bundle from `storage.googleapis.com/osv-vulnerabilities/<eco>/all.zip`, extracts every `MAL-*` advisory, and indexes them in a local SQLite database partitioned by ecosystem. A background task refreshes each bundle hourly; if one bundle fails the others stay fresh.

Per-version lookups during `npm install` / `pip install` hit the local DB — **zero outbound calls on the hot path**, which keeps installs fast and your dependency graph private.

To also catch advisories published since the last refresh, enable `PKGGATE_LIVE_FALLBACK_ENABLED=true`. The live API is then queried only for versions the mirror considers clean, batched via OSV's `querybatch` endpoint.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PKGGATE_MIRROR_ENABLED` | `true` | Enable local OSV mirror |
| `PKGGATE_MIRROR_DB` | `mirror.db` | SQLite path |
| `PKGGATE_MIRROR_REFRESH_SECONDS` | `3600` | Refresh interval |
| `PKGGATE_LIVE_FALLBACK_ENABLED` | `false` | Query OSV API for clean versions |
| `PKGGATE_OSV_BUNDLE_NPM` | public GCS URL | Override npm bundle source |
| `PKGGATE_OSV_BUNDLE_PYPI` | public GCS URL | Override PyPI bundle source |
| `PKGGATE_OSV_API` | `https://api.osv.dev/v1/query` | Live fallback endpoint |

---

## Policy engine

Policies live in `config/policy.yaml`. Example rules:

- `block_malicious` — hard-block OSV `MAL-*` advisories.
- `min_package_age_days` — block packages younger than _N_ days (typo-squat mitigation).
- `require_repository_url` — block packages without a repository link.
- `deny_postinstall` — block packages that ship lifecycle scripts.
- `allowlist` / `denylist` — explicit overrides.

Tune these to match your organization's risk appetite — small teams typically start with `block_malicious` + `min_package_age_days: 7`.

---

## Audit log

Every decision is appended to `./audit.log` as JSON Lines, ready for ingestion by any SIEM, log shipper, or `jq` pipeline:

```json
{"ts":"2026-04-20T10:12:03Z","action":"block","package":"passports-js","version":"0.0.1-security","rule":"block_malicious","source":"MAL-2024-88"}
```

---

## PyPI support

pkggate implements the [PEP 691](https://peps.python.org/pep-0691/) Simple Repository JSON API as a two-gate proxy:

1. **Simple index gate** (`GET /simple/<project>/`) — fetches the upstream index, runs intel + policy per version, drops denied files, rewrites surviving file URLs through the proxy, and caches SHA-256 hashes for the second gate.
2. **File gate** (`GET /packages/<path>`) — re-evaluates policy (last stop before bytes leave), verifies the SHA-256 hash against the simple-index claim, and serves the file. Lockfile-driven installs that skip the index trigger a one-shot prefetch to populate the hash cache.

Configure pip to use pkggate:

```ini
# pip.conf
[global]
index-url = http://127.0.0.1:8080/simple/
```

| Variable | Default | Description |
| --- | --- | --- |
| `PKGGATE_PYPI_ENABLED` | `true` | Enable the PyPI proxy |
| `PKGGATE_PYPI_UPSTREAM_SIMPLE` | `https://pypi.org/simple/` | Upstream simple index |
| `PKGGATE_PYPI_UPSTREAM_FILES` | `https://files.pythonhosted.org/` | Upstream file server |
| `PKGGATE_PYPI_PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Public URL of this proxy (used for URL rewriting) |
| `PKGGATE_PYPI_VERIFY_INTEGRITY` | `true` | Verify SHA-256 hash against simple-index claim |
| `PKGGATE_PYPI_MAX_BUFFER_BYTES` | `209715200` | Maximum file size buffered for verification (200 MiB) |

---

## Project status

**pkggate is an early-stage prototype.** It works end-to-end for npm and PyPI, but APIs, configuration keys, and on-disk formats may still change without notice. Production use is at your own risk — please pin versions and review the audit log.

Roadmap highlights:

- Hardening the policy engine and configuration schema.
- Cargo and Maven adapters (plugin point already exists at `src/pkggate/proxy/`).
- A small admin UI for the audit log.
- Pre-built container images and a Helm chart.

---

## Contributing

**Contributions are explicitly welcome.** This project is built for the community — small businesses, OSS maintainers, indie devs, and security teams who want supply-chain protection without an enterprise budget.

Helpful ways to contribute:

- **Try it in your stack** and open issues for anything that breaks or surprises you.
- **Add ecosystem adapters** (Cargo, Maven, RubyGems, Go modules).
- **Improve the policy engine** — new rules, better defaults, clearer error messages.
- **Documentation, examples, translations** — especially deployment guides for common environments (Kubernetes, Nomad, plain `systemd`).
- **Threat-intel integrations** beyond OSV.dev.

To contribute:

1. Fork the repository and create a feature branch.
2. Follow conventional commits where possible.
3. Open a pull request describing the change and the motivation.
4. Be kind in reviews — see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

If you're unsure where to start, open a discussion or an issue tagged `question` — we'll help you find a good first task.

---

## Code of Conduct

Participation in this project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its terms. Reports can be sent privately to the maintainer email listed in that document.

---

## Security

Found a vulnerability in pkggate itself? **Please do not file a public issue.** Email the maintainer (see `CODE_OF_CONDUCT.md`) with details and we will respond as quickly as we can.

For malicious-package reports, file them upstream with [OSV.dev](https://osv.dev/) or the [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) project so the whole ecosystem benefits.

---

## License

[MIT](LICENSE) — use it, fork it, ship it.
