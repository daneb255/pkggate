# Installation

pkggate can be run via Docker (recommended), Docker Compose, or directly from source.

---

## Docker (recommended)

Pull the published image from GitHub Container Registry:

```bash
docker pull ghcr.io/daneb255/pkggate:latest
```

Run with default settings (listens on port 8080):

```bash
docker run -p 8080:8080 ghcr.io/daneb255/pkggate:latest
```

Mount a custom policy file:

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config/policy.yaml:/app/config/policy.yaml \
  ghcr.io/daneb255/pkggate:latest
```

---

## Docker Compose

The included `docker-compose.yml` builds locally if no image is present:

```bash
docker compose up
```

To use the pre-built image instead of building from source, set the image tag in your compose override:

```yaml
# docker-compose.override.yml
services:
  pkggate:
    image: ghcr.io/daneb255/pkggate:latest
```

---

## From source

**Requirements:** Python 3.12+

```bash
git clone https://github.com/daneb255/pkggate.git
cd pkggate
pip install -e ".[dev]"
```

Start the proxy:

```bash
python -m pkggate
```

Or via the Makefile:

```bash
make run
```

---

## Verifying the installation

Once running, confirm the proxy is healthy:

```bash
curl http://localhost:8080/healthz
```

Expected response: `{"status":"ok"}`
