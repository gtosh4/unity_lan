# UnityLAN coordinator image.
# Build from the repo root:
#   docker build -f packaging/docker/coordinator.Dockerfile -t unitylan-coordinator .
# Run (bind = "0.0.0.0:8080", database = "/data/coordinator.db" in your config):
#   docker run -p 8080:8080 \
#     -v $PWD/coordinator.toml:/etc/unitylan/coordinator.toml:ro \
#     -v unitylan-data:/data unitylan-coordinator

# Full (non-slim) image: the coordinator's sqlx/sqlite + rustls(ring) build needs a C toolchain.
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p unitylan-coordinator

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/unitylan-coordinator /usr/bin/unitylan-coordinator
# sqlite db lives here; mount a volume to persist it.
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/bin/unitylan-coordinator"]
CMD ["/etc/unitylan/coordinator.toml"]
