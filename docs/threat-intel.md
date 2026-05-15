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

When enabled, the live API is only called for versions that passed the local mirror check — it is **never** called for versions already known to be malicious. Each lookup hits the OSV `/v1/query` endpoint directly.

!!! note
    The live fallback introduces outbound calls on the hot path. In environments with strict egress controls, leave it disabled and rely on the mirror's hourly refresh cycle instead.

---

## Advisory coverage

pkggate queries the OSV API for all advisories matching a package version. Two categories are actionable:

| Advisory type | How pkggate uses it |
| --- | --- |
| `MAL-*` | Marks the package as **malicious** — blocked by `block_malicious: true` |
| `GHSA-*`, `CVE-*`, and others | CVSS base scores are extracted and stored on the intel verdict — optionally blocked by `max_cvss_score` |

CVSS v2 and v3 vectors are parsed from the `severity` field of each advisory. The highest score across all returned advisories is recorded. If it meets or exceeds the configured `max_cvss_score` threshold, the request is denied independently of the malicious flag.

!!! note
    The local OSV mirror indexes `MAL-*` advisories only. CVSS scores for non-malicious advisories come from the **live OSV API** (`/v1/query` endpoint). Enable `PKGGATE_LIVE_FALLBACK_ENABLED=true` to activate this path; without it, `max_cvss_score` only applies to packages that are also checked by the live API.
