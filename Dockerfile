# Builder stage: compile and install dependencies
FROM python:3.14-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --user --no-cache-dir .


# Runtime stage: minimal final image
FROM python:3.14-slim

WORKDIR /app

COPY --from=builder /root/.local /root/.local
COPY config ./config

ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PKGGATE_HOST=0.0.0.0 \
    PKGGATE_PORT=8080 \
    PKGGATE_POLICY_FILE=/app/config/policy.yaml \
    PKGGATE_AUDIT_LOG=/app/audit.log

RUN useradd -m -u 1000 pkggate && chown -R pkggate:pkggate /app

USER pkggate

EXPOSE 8080

CMD ["pkggate"]
