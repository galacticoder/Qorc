FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -o Acquire::ForceIPv4=true update && apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends build-essential pkg-config libevent-dev libssl-dev zlib1g-dev liblzma-dev libzstd-dev patch ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY tor-0.4.9.14.tar.gz /build/source.tar.gz
COPY 0001-retry-hsdesc-upload.patch /build/publication.patch

RUN echo '182449ac1c8ff43278da27b69b02040e11d03d0327db6d9126e4190ec6235e4a  source.tar.gz' | sha256sum -c - \
    && echo 'fe4e842638d96977032468f6c652af1c93d87ab347bf57799f6d3f65c07ffb6f  publication.patch' | sha256sum -c - \
    && tar -xzf source.tar.gz \
    && cd tor-0.4.9.14 \
    && patch -p1 < /build/publication.patch \
    && ./configure --disable-asciidoc \
    && make -j2 src/app/tor src/test/test \
    && ./src/test/test hs_service/upload_retry_schedule \
    && mkdir -p /output \
    && cp src/app/tor /output/tor \
    && ./src/app/tor --version
