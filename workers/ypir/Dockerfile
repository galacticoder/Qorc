# YPIR tier-2 discovery-blob worker (oblivious fetch of a discovery blob by slot — no handle leaked).
# Built from the vendored crate in this directory (workers/ypir) with the pinned nightly toolchain.
# Standalone build: outside the repo, so this crate's own .cargo/config (target-cpu=native) applies
# and the repo-root config can't override it. The runtime HOST must have AVX-512 (server.rs/kernel.rs
# matmul); the device-side ypir_client is built/bundled separately and is AVX-512-free.

FROM rust:1.77-bookworm AS build
RUN rustup toolchain install nightly-2024-02-07 --profile minimal --component rust-std
WORKDIR /build
# Build deps for the C++ matmul (build.rs: cc + -march=native) and the git dep fetch.
RUN apt-get update && apt-get install -y --no-install-recommends g++ build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . /build/ypir
WORKDIR /build/ypir
# rust-toolchain.toml pins nightly-2024-02-07; .cargo/config.toml sets target-cpu=native.
RUN cargo build --release --bin ypir_worker

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/ypir/target/release/ypir_worker /usr/local/bin/ypir-worker
EXPOSE 8788
ENV YPIR_WORKER_ADDR=0.0.0.0:8788
HEALTHCHECK --interval=5s --timeout=3s --retries=30 \
    CMD curl -fsS "http://127.0.0.1:8788/health" || exit 1
CMD ["ypir-worker"]
