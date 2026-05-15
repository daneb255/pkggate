# Environment Variables

All pkggate settings can be controlled via environment variables. Pass them to Docker with `-e` flags or set them in your shell before running from source.

---

## OSV mirror

| Variable | Default | Description |
|---|---|---|
| `PKGGATE_MIRROR_ENABLED` | `true` | Enable the local OSV mirror |
| `PKGGATE_MIRROR_DB` | `mirror.db` | Path to the SQLite mirror database |
| `PKGGATE_MIRROR_REFRESH_SECONDS` | `3600` | How often (seconds) to re-download OSV bundles |
| `PKGGATE_LIVE_FALLBACK_ENABLED` | `false` | Query the OSV API for versions the mirror considers clean |
| `PKGGATE_OSV_BUNDLE_NPM` | GCS public URL | Override the npm OSV bundle source |
| `PKGGATE_OSV_BUNDLE_PYPI` | GCS public URL | Override the PyPI OSV bundle source |
| `PKGGATE_OSV_API` | `https://api.osv.dev/v1/query` | Live fallback endpoint |

---

## PyPI proxy

| Variable | Default | Description |
|---|---|---|
| `PKGGATE_PYPI_ENABLED` | `true` | Enable the PyPI proxy |
| `PKGGATE_PYPI_UPSTREAM_SIMPLE` | `https://pypi.org/simple/` | Upstream Simple index URL |
| `PKGGATE_PYPI_UPSTREAM_FILES` | `https://files.pythonhosted.org/` | Upstream file server |
| `PKGGATE_PYPI_PUBLIC_BASE_URL` | `http://127.0.0.1:8080` | Public base URL of this proxy (used for URL rewriting) |
| `PKGGATE_PYPI_VERIFY_INTEGRITY` | `true` | Verify SHA-256 hash against the Simple index claim |
| `PKGGATE_PYPI_MAX_BUFFER_BYTES` | `209715200` | Maximum file size (bytes) buffered for integrity verification (200 MiB) |

---

## Example: Docker Compose with overrides

```yaml
services:
  pkggate:
    image: ghcr.io/daneb255/pkggate:latest
    ports:
      - "8080:8080"
    environment:
      PKGGATE_MIRROR_REFRESH_SECONDS: "1800"
      PKGGATE_LIVE_FALLBACK_ENABLED: "true"
      PKGGATE_PYPI_PUBLIC_BASE_URL: "http://pkggate.internal:8080"
    volumes:
      - ./config/policy.yaml:/app/config/policy.yaml
      - pkggate-data:/app/data

volumes:
  pkggate-data:
```
