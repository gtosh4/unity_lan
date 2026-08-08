# UnityLAN coordinator image.
# Build from the repo root:
#   docker build -f packaging/docker/coordinator.Dockerfile -t unitylan-coordinator .
# Run (bind = "0.0.0.0:8080", database = "/data/coordinator.db" in your config):
#   docker run -p 8080:8080 \
#     -v $PWD/config:/etc/unitylan:ro \
#     -v unitylan-data:/data unitylan-coordinator
# Mount the config DIRECTORY, not the file: a single-file bind mount pins the host inode, so an
# atomic-save editor (temp + rename: vim, sed -i) swaps it and the container serves stale config.

# Where the binary comes from. `build` (the default) compiles it here, so a plain `docker build` off
# a clean checkout works with no prerequisites. CI passes `--build-arg BINARY_SRC=prebuilt` instead:
# it has already cross-compiled the coordinator to x86_64-unknown-linux-musl under the warm cargo
# cache that release.yml restores, and recompiling it here would throw that away — the in-image build
# is always cold, because BuildKit cache mounts live in buildkitd state that a fresh CI runner does
# not have, and `cache-to` does not export them.
ARG BINARY_SRC=build

# Alpine/musl: a static build lets the runtime be a tiny alpine (no glibc, no shared libs).
# build-base supplies the C toolchain the bundled sqlite (libsqlite3-sys) and ring need.
FROM rust:1.96-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
# Cache mounts keep the registry + target/ across *local* rebuilds, so only what changed recompiles.
# They do nothing in CI (see BINARY_SRC above). The binary must be copied OUT inside this RUN:
# target/ is a cache mount and vanishes when it ends, so a later `COPY --from=build /src/target/...`
# would not find it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p unitylan-coordinator \
    && cp target/release/unitylan-coordinator /unitylan-coordinator

# The CI path: take the musl binary release.yml staged into packaging/dist. `scratch` so nothing is
# pulled — this stage exists only to hand a file to the runtime stage below. .dockerignore excludes
# packaging/dist wholesale and re-admits exactly this one path.
FROM scratch AS prebuilt
COPY packaging/dist/unitylan-coordinator /unitylan-coordinator

# Resolves to whichever of the two stages above BINARY_SRC named. BuildKit only builds the stages
# the target actually reaches, so the unselected one never runs.
FROM ${BINARY_SRC} AS binary

FROM alpine:3.20
# ca-certificates: outbound TLS to Discord (rustls-native-certs reads the system trust store).
# The HEALTHCHECK below uses busybox `wget`, already in the base image — no extra package.
RUN apk add --no-cache ca-certificates \
    && adduser -S -D -H -h /data unitylan \
    && install -d -o unitylan /data
COPY --from=binary /unitylan-coordinator /usr/bin/unitylan-coordinator

# Run unprivileged: the coordinator carries no traffic and needs no root. `unitylan` owns /data so
# a fresh named volume (Docker seeds volume ownership from the mountpoint dir) is writable.
# sqlite db lives here; mount a volume to persist it.
VOLUME /data
USER unitylan

EXPOSE 8080
# Liveness against the control API's /healthz (returns "ok"). Assumes the config's `bind` keeps the
# default :8080; override with --health-cmd if you bind elsewhere.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/bin/unitylan-coordinator"]
CMD ["/etc/unitylan/coordinator.toml"]
