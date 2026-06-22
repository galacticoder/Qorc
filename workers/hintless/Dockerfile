# Builds the Qor hintless-SimplePIR worker (and the client helper) from the
# VENDORED hintless_pir source (./upstream, pinned in hintless.lock.json) plus
# our reviewed overlay in ./src — no GitHub clone at build time. Built with
# bazel -c opt. The runtime image ships only the worker binary.
#
# Bazel still resolves its module dependencies (SHELL, Abseil, Eigen, BoringSSL,
# protobuf, ...) on a clean build, pinned by upstream/MODULE.bazel.lock; that
# step is cached in this image layer, so it is not re-fetched on rebuilds unless
# the sources change.

# ---- build stage ----------------------------------------------------------
FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl g++ build-essential python3 unzip zip \
    && rm -rf /var/lib/apt/lists/*

# Pinned Bazelisk -> Bazel launcher.
RUN curl -fsSL -o /usr/local/bin/bazel \
        https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel

WORKDIR /src

# Vendored pinned hintless_pir source.
COPY upstream/ /src/

# Overlay our reviewed sources as the //qor package.
COPY src/qor_pir_common.h qor/qor_pir_common.h
COPY src/qor_pir_worker.cc qor/qor_pir_worker.cc
COPY src/qor_pir_client.cc qor/qor_pir_client.cc
COPY third_party/httplib.h qor/third_party/httplib.h
COPY third_party/json.hpp qor/third_party/json.hpp
COPY BUILD.overlay qor/BUILD

# MUST be -c opt (see hintless.lock.json).
RUN bazel build -c opt //qor:qor_pir_worker //qor:qor_pir_client \
    && mkdir -p /out \
    && cp bazel-bin/qor/qor_pir_worker /out/qor-pir-worker \
    && cp bazel-bin/qor/qor_pir_client /out/qor-pir-client \
    && chmod +x /out/qor-pir-worker /out/qor-pir-client

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10031 --no-create-home qorpir

COPY --from=build /out/qor-pir-worker /usr/local/bin/qor-pir-worker
COPY --from=build /out/qor-pir-client /usr/local/bin/qor-pir-client

USER qorpir
ENV QOR_PIR_BIND=0.0.0.0:8787
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:8787/health" || exit 1
ENTRYPOINT ["/usr/local/bin/qor-pir-worker"]
