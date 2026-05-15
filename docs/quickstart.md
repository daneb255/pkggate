# Quick Start

Get pkggate running and protecting your installs in under 5 minutes.

---

## 1. Start pkggate

=== "Docker Compose"

    ```bash
    docker compose up
    ```

=== "Docker"

    ```bash
    docker run -p 8080:8080 ghcr.io/daneb255/pkggate:latest
    ```

=== "Source"

    ```bash
    pip install -e ".[dev]"
    python -m pkggate
    ```

pkggate is now listening on `http://localhost:8080`.

---

## 2. Point npm at pkggate

```bash
echo "registry=http://localhost:8080/" > ~/.npmrc

# Clear the cache once — npm bypasses the proxy for cached tarballs
npm cache clean --force

npm install express
```

You should see `[pkggate] allow express@...` in the proxy logs.

---

## 3. Point pip at pkggate

=== "Command line"

    ```bash
    pip config set global.index-url http://localhost:8080/simple/
    pip install requests
    ```

=== "pip.conf"

    ```ini
    [global]
    index-url = http://localhost:8080/simple/
    ```

---

## 4. Verify a block

Install a known-safe test package to confirm the proxy is intercepting requests, then check the audit log:

```bash
tail -f audit.log | jq .
```

Each line is a JSON object:

```json
{"ts":"2026-04-20T10:12:03Z","action":"allow","package":"express","version":"4.18.2","rule":null,"source":null}
```

A malicious package would show:

```json
{"ts":"2026-04-20T10:12:03Z","action":"block","package":"passports-js","version":"0.0.1","rule":"block_malicious","source":"MAL-2024-88"}
```

---

---

## Use in CI/CD (GitHub Actions)

Run pkggate as a service container so installs are protected in CI, then generate an SBOM with [unravel-sbom](https://github.com/daneb255/unravel-sbom) for continuous monitoring:

```yaml
services:
  pkggate:
    image: ghcr.io/daneb255/pkggate:latest
    ports:
      - 8080:8080

steps:
  - uses: actions/checkout@v4

  - name: Install dependencies via pkggate
    env:
      npm_config_registry: http://localhost:8080/
    run: npm ci

  - name: Generate and upload SBOM
    env:
      DTRACK_URL: ${{ secrets.DTRACK_URL }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
    run: |
      pip install unravel-sbom
      unravel-sbom scan . -f cyclonedx \
        --dtrack-project "${{ github.repository }}" \
        --dtrack-version "${{ github.ref_name }}" \
        --dtrack-wait
```

This gives you two layers of protection in every CI run: pkggate blocks malicious packages at install time; unravel-sbom inventories everything that made it in and uploads it to Dependency-Track for continuous CVE monitoring.

For PyPI projects, swap the install step:

```yaml
  - name: Install dependencies via pkggate
    env:
      PIP_INDEX_URL: http://localhost:8080/simple/
    run: pip install -r requirements.txt
```

---

## Next steps

- [Policy Engine](policy.md) — tune which packages are blocked and why.
- [Configuration](configuration.md) — environment variables for the OSV mirror and proxy settings.
- [Audit Log](audit-log.md) — integrate audit events with your SIEM or log pipeline.
