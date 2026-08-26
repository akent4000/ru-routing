# syntax=docker/dockerfile:1
#
# Reproducible builder image for the RU routing pipeline.
#
# Everything that determines build output is pinned here, not floating:
#
#   - the base Python image, by content digest (not just a tag);
#   - the Go toolchain, by tag (used both to build DLC/geoip from source and
#     to run tools/re2check -- the exact RE2 regex validator normalize.py
#     shells out to via `go run`, see GoRegexValidator);
#   - v2fly/domain-list-community ("dlc") and v2fly/geoip, built from source
#     at pinned upstream commit SHAs (build args, overridable but default to
#     the reviewed values below);
#   - sing-box, mihomo, and Xray-core release binaries, downloaded from
#     GitHub Releases at a pinned version tag and verified against a pinned
#     SHA-256 checksum before use.
#
# NOTE: the base image digest and the four pinned release/commit values
# below were resolved from live upstream metadata during Task 10's
# implementation (2026-08-26). This image was built and exercised
# end-to-end in that same session: `docker compose run --rm builder build
# --fixtures tests/fixtures/upstreams/registry --dist /work/output/dist`
# completed successfully with the real dlc/geoip/sing-box/mihomo/xray
# binaries (no --fake-native-tools), and two independent such builds
# produced a byte-for-byte identical dist/ tree (including manifest.json
# and SHA256SUMS) -- see the Task 10 report for the exact commands and
# output. Note --dist points inside docker-compose.yml's ./output mount
# (/work/output/dist), not at the mount point itself: generate_all
# atomically replaces its --dist directory via os.replace(), and Linux
# refuses to rename() a bind-mount point, so the mount must be a parent
# directory one level up from the atomic-swap target.
# These pins will still go stale over time (upstream releases move on);
# treat a future digest/checksum mismatch at build time as a signal to
# re-pin deliberately after re-verifying, not to bypass verification.

ARG PYTHON_DIGEST=sha256:2fc9207f64226cb05ac317cee0bab6fa55a9ea311ce5a086baddd4b4a83c2d3c
FROM python:3.11-slim-bookworm@${PYTHON_DIGEST} AS base

# --- Build stage: compile Go tools from pinned source revisions ------------
# v2fly/domain-list-community's go.mod currently requires Go >= 1.25.12.
FROM golang:1.25-bookworm AS go-builder

ARG DLC_COMMIT=f56684b9d1d38d72fd3eade7eab47b1b7c3f8f44
ARG GEOIP_COMMIT=171cde937eea24a9a4a81349cc55109167e594cc

WORKDIR /src/dlc
RUN git init -q . \
    && git remote add origin https://github.com/v2fly/domain-list-community.git \
    && git fetch --depth 1 origin "${DLC_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dlc .

WORKDIR /src/geoip
RUN git init -q . \
    && git remote add origin https://github.com/v2fly/geoip.git \
    && git fetch --depth 1 origin "${GEOIP_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/geoip .

# --- Build stage: download and verify pinned release binaries --------------
FROM debian:bookworm-slim AS tool-fetcher

ARG SING_BOX_VERSION=1.13.19
ARG SING_BOX_SHA256=ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1
ARG MIHOMO_VERSION=1.19.30
ARG MIHOMO_SHA256=cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84
ARG XRAY_VERSION=26.3.27
ARG XRAY_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /out
RUN set -eu; \
    curl -fsSL -o sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz"; \
    echo "${SING_BOX_SHA256}  sing-box.tar.gz" | sha256sum -c -; \
    tar -xzf sing-box.tar.gz --strip-components=1 -C . \
        "sing-box-${SING_BOX_VERSION}-linux-amd64/sing-box"; \
    rm sing-box.tar.gz

RUN set -eu; \
    curl -fsSL -o mihomo.gz \
        "https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/mihomo-linux-amd64-v${MIHOMO_VERSION}.gz"; \
    echo "${MIHOMO_SHA256}  mihomo.gz" | sha256sum -c -; \
    gunzip -c mihomo.gz > mihomo; \
    chmod +x mihomo; \
    rm mihomo.gz

RUN set -eu; \
    curl -fsSL -o xray.zip \
        "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"; \
    echo "${XRAY_SHA256}  xray.zip" | sha256sum -c -; \
    unzip -q xray.zip xray -d .; \
    rm xray.zip

# --- Final image -------------------------------------------------------
FROM base AS final

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Go itself stays in the final image: normalize.py's GoRegexValidator
# shells out to `go run tools/re2check/main.go` at build/validate time, not
# just at image-build time (see src/ru_routing/normalize.py).
COPY --from=golang:1.25-bookworm /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOCACHE=/tmp/gocache

COPY --from=go-builder /out/dlc /usr/local/bin/dlc
COPY --from=go-builder /out/geoip /usr/local/bin/geoip
COPY --from=tool-fetcher /out/sing-box /usr/local/bin/sing-box
COPY --from=tool-fetcher /out/mihomo /usr/local/bin/mihomo
COPY --from=tool-fetcher /out/xray /usr/local/bin/xray
RUN chmod +x /usr/local/bin/dlc /usr/local/bin/geoip \
        /usr/local/bin/sing-box /usr/local/bin/mihomo /usr/local/bin/xray

WORKDIR /work
COPY pyproject.toml /work/pyproject.toml
COPY src /work/src
COPY tools /work/tools
COPY examples /work/examples
COPY config /work/config
COPY tests /work/tests
RUN pip install --no-cache-dir /work

# Xray resolves relative-looking `ext:` domain/geoip file references (used
# by validate.py's generated test config) against XRAY_LOCATION_ASSET,
# defaulting to the xray binary's own directory when unset. dist paths are
# absolute, but Xray's Go-side path join still needs an asset root that
# will not accidentally shadow them; "/" makes an already-absolute `ext:`
# path resolve to itself.
ENV XRAY_LOCATION_ASSET=/

ENTRYPOINT ["ru-routing"]
CMD ["--help"]
