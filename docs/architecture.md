# Architecture

pkggate is a Python proxy server that intercepts package manager traffic, evaluates each request against threat intelligence and policy rules, and either forwards or blocks the request.

---

## Request flow

```
Package Manager
      |
      v
  pkggate proxy  (HTTP server, port 8080)
      |
      +---> Policy Engine  <--- policy.yaml (hot-reloaded)
      |           |
      |     OSV Mirror DB (SQLite)
      |           |
      |     [optional] OSV Live API
      |
      v
  Upstream Registry (npmjs.com / pypi.org)
      |
      v
  Package Manager  (tarball / metadata)
```

---

## Components

### Proxy layer (`src/pkggate/proxy/`)

Ecosystem-specific adapters that implement the registry protocol:

- **npm adapter** — implements the npm registry HTTP API. Intercepts metadata responses to strip malicious versions and tarball requests for a final pre-delivery check.
- **PyPI adapter** — implements [PEP 691](https://peps.python.org/pep-0691/) Simple Repository JSON API. Intercepts the simple index to rewrite URLs and filter versions, and the file endpoint to verify integrity.

Each adapter is a plugin point — new ecosystems (Cargo, Maven, RubyGems) can be added without touching the core.

### Policy engine (`src/pkggate/policy/`)

Evaluates a request against the configured rules in `config/policy.yaml`. Returns `(action, rule, source)` — `allow` or `block`, plus which rule triggered and the advisory ID if applicable.

The policy file is watched for changes and hot-reloaded without restarting the proxy.

### OSV mirror (`src/pkggate/mirror/`)

Downloads OSV advisory bundles from GCS, extracts `MAL-*` advisories, and stores them in a local SQLite database. A background task refreshes each ecosystem's bundle on the configured interval. Incremental updates mean only changed advisories are re-processed.

### Audit logger (`src/pkggate/audit/`)

Appends a JSON Lines record to `audit.log` for every proxy decision.

---

## Data flow: npm install

1. `npm install express` sends `GET /express` to pkggate.
2. pkggate fetches `https://registry.npmjs.org/express` upstream.
3. For each version in the response, the policy engine checks the OSV mirror.
4. Versions with `MAL-*` advisories are removed from the `versions` map.
5. The filtered metadata is returned to `npm`.
6. `npm` picks a version and requests `GET /express/-/express-4.18.2.tgz`.
7. Policy is evaluated again (last-stop check).
8. If clean, the tarball is proxied from upstream.
9. Each decision is written to `audit.log`.

## Data flow: pip install

1. `pip install requests` sends `GET /simple/requests/` to pkggate.
2. pkggate fetches the upstream Simple index.
3. Policy is evaluated per file entry; denied versions are removed.
4. Surviving file URLs are rewritten to point back through pkggate.
5. `pip` selects a version and requests the rewritten file URL.
6. pkggate re-evaluates policy, fetches the file upstream, verifies the SHA-256 hash, and streams it to `pip`.

---

## Extending pkggate

To add a new ecosystem adapter:

1. Create a new module under `src/pkggate/proxy/`.
2. Implement the upstream protocol (metadata + file endpoints).
3. Call the policy engine for each version/file decision.
4. Register the adapter's routes in the main application.

The policy engine and OSV mirror are ecosystem-agnostic — the adapter only needs to map ecosystem-specific concepts (version strings, file hashes) onto the common `check(ecosystem, package, version)` interface.
