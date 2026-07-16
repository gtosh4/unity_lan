# UnityLAN coordinator image.
# Build from the repo root:
#   docker build -f packaging/docker/coordinator.Dockerfile -t unitylan-coordinator .
# Run (bind = "0.0.0.0:8080", database = "/data/coordinator.db" in your config):
#   docker run -p 8080:8080 \
#     -v $PWD/coordinator.toml:/etc/unitylan/coordinator.toml:ro \
#     -v unitylan-data:/data unitylan-coordinator

# Alpine/musl: a static build lets the runtime be a tiny alpine (no glibc, no shared libs).
# build-base supplies the C toolchain the bundled sqlite (libsqlite3-sys) and ring need.
FROM rust:1.96-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
RUN cargo build --release -p unitylan-coordinator

FROM alpine:3.20
# ca-certificates: outbound TLS to Discord (rustls-native-certs reads the system trust store).
# The HEALTHCHECK below uses busybox `wget`, already in the base image — no extra package.
RUN apk add --no-cache ca-certificates \
    && adduser -S -D -H -h /data unitylan \
    && install -d -o unitylan /data
COPY --from=build /src/target/release/unitylan-coordinator /usr/bin/unitylan-coordinator

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
