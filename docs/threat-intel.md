# Threat Intelligence

pkggate uses [OSV.dev](https://osv.dev/) as its primary threat-intelligence source, operated as a local mirror to keep installs fast and your dependency graph private.

---

## Local OSV mirror

At startup, pkggate downloads each ecosystem's OSV bundle from Google Cloud Storage:

```
storage.googleapis.com/osv-vulnerabilities/<ecosystem>/all.zip
```

It extracts every `MAL-*` (malicious package) advisory and indexes them in a local SQLite database partitioned by ecosystem. A background task refreshes each bundle on the interval configured by `PKGGATE_MIRROR_REFRESH_SECONDS` (default: 1 hour). If one bundle fails to refresh, the others continue unaffected.

**Benefits of the local mirror:**

- **Zero outbound calls on the hot path** — per-version lookups hit the local DB only.
- **Fast installs** — no network round-trip to OSV on every `npm install` or `pip install`.
- **Privacy** — your dependency graph never leaves your infrastructure.

---

## Live fallback

Set `PKGGATE_LIVE_FALLBACK_ENABLED=true` to also query the OSV API for versions the local mirror considers clean. This catches advisories published since the last bundle refresh.

When enabled, the live API is only called for versions that passed the local mirror check — it is **never** called for versions already known to be malicious. Requests are batched via OSV's `querybatch` endpoint to minimize latency.

!!! note
    The live fallback introduces outbound calls on the hot path. In environments with strict egress controls, leave it disabled and rely on the mirror's hourly refresh cycle instead.

---

## Advisory coverage

pkggate currently indexes and enforces `MAL-*` advisories only. These are advisories in the OSV database that denote packages confirmed as malicious (as opposed to packages with known vulnerabilities in specific versions).

Other OSV advisory types (`GHSA-*`, `CVE-*`, etc.) are not currently used by the policy engine but may be added in a future release.

---

## Incremental mirror updates

pkggate supports incremental mirror updates — on each refresh cycle it only downloads and processes advisories that have changed since the last run. This keeps the refresh fast even as the OSV database grows.
