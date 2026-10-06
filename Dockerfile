# GraphSentinel — detection API
#
# Multi-stage so the runtime image carries no build toolchain, and CPU-only
# torch so the image does not ship ~2GB of CUDA libraries a CPU-serving
# container never executes.
#
# The original single-stage contract is preserved deliberately: same port
# (8000), same `graphsentinel-api` entrypoint, same extras, same non-root
# user, same /app/artifacts and /app/data layout. compose.yaml and the README
# depend on all of it.

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# CPU wheel first, so the resolver cannot pull the CUDA build in behind it.
RUN python -m pip install --upgrade pip \
    && python -m pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && python -m pip install ".[api,data,ml,dashboard]"

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    GRAPHSENTINEL_HOST=0.0.0.0 \
    GRAPHSENTINEL_PORT=8000

WORKDIR /app

RUN groupadd --system graphsentinel \
    && useradd --system --gid graphsentinel --home-dir /app graphsentinel

COPY --from=builder /opt/venv /opt/venv
COPY configs ./configs

RUN mkdir -p /app/artifacts /app/data \
    && chown -R graphsentinel:graphsentinel /app

# Mounted, never baked. Checkpoints, entity dictionaries and warm-state
# snapshots are tenant-specific; baking them would put customer-derived state
# in a registry and make the image unshareable.
VOLUME ["/app/artifacts", "/app/data"]

USER graphsentinel
EXPOSE 8000

# Readiness, not liveness. /health says the process is up; /ready says it
# should take traffic AND reports whether it is running on cold state, which
# costs roughly half the achievable PR-AUC (see docs/ONBOARDING.md).
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=4)"

# One worker on purpose. The detection path holds cumulative per-entity state
# in process -- the causal feature engine and the TGN's node memory. Multiple
# workers would each hold a divergent copy and score the same stream
# inconsistently, so scale is per-tenant rather than per-process.
CMD ["graphsentinel-api", "--host", "0.0.0.0", "--port", "8000"]
