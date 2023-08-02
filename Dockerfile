FROM rust:1.70.0-slim-buster AS builder

RUN apt-get update && \
    apt-get install -y build-essential wget pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

ENV SCCACHE_VERSION=0.5.0

RUN ARCH= && alpineArch="$(dpkg --print-architecture)" \
    && case "${alpineArch##*-}" in \
    amd64) \
    ARCH='x86_64' \
    ;; \
    arm64) \
    ARCH='aarch64' \
    ;; \
    *) ;; \
    esac \
    && wget -O sccache.tar.gz https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-${ARCH}-unknown-linux-musl.tar.gz \
    && tar xzf sccache.tar.gz \
    && mv sccache-v*/sccache /usr/local/bin/sccache \
    && chmod +x /usr/local/bin/sccache

ENV RUSTC_WRAPPER=/usr/local/bin/sccache

WORKDIR /build

ARG BUILD_TAG
ARG BUILD_TIMESTAMP

ENV BUILD_TAG = ${BUILD_TAG}
ENV BUILD_TIMESTAMP = ${BUILD_TIMESTAMP}

RUN cargo init --name temp-builder

COPY . .

RUN --mount=type=cache,target=/root/.cache cargo fetch && \
    cargo build && \
    cargo build --release && \
    rm src/*.rs

# Build the project
COPY src src

RUN --mount=type=cache,target=/root/.cache touch src/main.rs && \
    cargo build --release


# Distribute the binary
FROM gcr.io/distroless/cc-debian11 AS release

WORKDIR /dist

COPY --from=builder /build/target/release/sp-security ./sp-security

CMD ["/dist/sp-security"]