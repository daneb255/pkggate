# Builder stage: compile and install dependencies
FROM python:3.14-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --prefix=/opt/pkggate .


# Runtime stage: minimal final image
FROM python:3.14-slim

WORKDIR /app

COPY --from=builder /opt/pkggate /opt/pkggate
COPY config ./config

ENV PATH=/opt/pkggate/bin:$PATH \
    PYTHONPATH=/opt/pkggate/lib/python3.14/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PKGGATE_HOST=0.0.0.0 \
    PKGGATE_PORT=8080 \
    PKGGATE_POLICY_FILE=/app/config/policy.yaml \
    PKGGATE_AUDIT_LOG=/app/audit.log

RUN useradd -m -u 1000 pkggate \
    && mkdir -p /app/data \
    && chown -R pkggate:pkggate /app

USER pkggate

EXPOSE 8080

CMD ["pkggate"]
