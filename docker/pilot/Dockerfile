# syntax=docker/dockerfile:1
#
# Local pilot acceptance image. DEVELOPMENT ONLY.
#
# Packages the host prerequisites of docs/operations/local-pilot-acceptance.md
# (Node 24, Python 3.12 via uv, PostgreSQL 18, Circom 2.2.2) with the built
# workspaces, so `docker compose -f compose.pilot.yaml up` reproduces the
# source-checkout acceptance run without installing them on the host.
#
# The proving keys it generates are unapproved development artifacts. This image
# is not a deployment of the API and must not be exposed to a network or given
# real customer data.

FROM ghcr.io/astral-sh/uv:0.12.9 AS uv

FROM node:24-bookworm

ARG CIRCOM_VERSION=2.2.2
ARG CIRCOM_SHA256=f3d8d1fdbc123779b80e210c909ee941d7a1e130c70365524646b48b8b0fe9d5

# PostgreSQL 18 from the PostgreSQL Global Development Group apt repository.
# The cluster created by the package is unused: the acceptance runner owns a
# private, socket-only cluster under its output directory.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl --fail --location --silent --show-error \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-18 \
    && rm -rf /var/lib/apt/lists/*

# Circom: the same release binary and SHA-256 pin as CI.
RUN curl --fail --location --max-time 120 \
        "https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}/circom-linux-amd64" \
        -o /tmp/circom \
    && echo "${CIRCOM_SHA256}  /tmp/circom" | sha256sum --check \
    && install /tmp/circom /usr/local/bin/circom \
    && rm /tmp/circom \
    && circom --version

COPY --from=uv /uv /usr/local/bin/uv

# PostgreSQL refuses to run as root; the base image's unprivileged user owns the run.
RUN install -d -o node -g node /workspace /data
USER node
WORKDIR /workspace
ENV UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/home/node/.uv-python \
    npm_config_update_notifier=false

# Dependency layers first, from the committed lockfiles.
COPY --chown=node:node . .
RUN npm exec --yes --package=npm@11.9.0 -- npm ci \
    && uv sync --frozen --extra dev --python 3.12 \
    && npm run build

VOLUME /data
ENTRYPOINT ["bash", "docker/pilot/run-pilot.sh"]
