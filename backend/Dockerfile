# Aegis-Net backend image. Build context: repository root.
#   docker build -f backend/Dockerfile -t aegis-backend .

# ---- Stage 1: compile and test the C call-analysis library -------------------------------
FROM python:3.12-slim AS callanalyzer
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev cmake make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY c-library/ c-library/
RUN cmake -S c-library -B /build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /build -j"$(nproc)" \
 && ctest --test-dir /build --output-on-failure \
 && cmake --install /build --prefix /opt/callanalyzer

# ---- Stage 2: runtime ----------------------------------------------------------------------
FROM python:3.12-slim AS runtime
# git is required by the DevSecOps agent's sandboxed workspaces.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 aegis \
 && mkdir -p /data && chown aegis:aegis /data
COPY --from=callanalyzer /opt/callanalyzer/lib/ /usr/local/lib/
RUN ldconfig
WORKDIR /app
COPY backend/requirements.txt backend/requirements-llm.txt backend/
RUN pip install --no-cache-dir --root-user-action=ignore \
      -r backend/requirements.txt -r backend/requirements-llm.txt
COPY backend/ backend/
COPY demo-workspace/ demo-workspace/
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_DATA_DIR=/data \
    AGENT_WORKSPACE_ROOT=/data/agent-workspaces
USER aegis
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"
ENTRYPOINT ["/app/backend/docker-entrypoint.sh"]
