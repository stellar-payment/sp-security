FROM rust:1.70.0-slim-buster AS builder

RUN apt-get update && \
    apt-get install -y build-essential wget pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock /app/

RUN cargo new /app/

# WORKDIR /build
WORKDIR /app
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

COPY ./src /app/src

ARG BUILD_TAG
ARG BUILD_TIMESTAMP

ENV BUILD_TAG = ${BUILD_TAG}
ENV BUILD_TIMESTAMP = ${BUILD_TIMESTAMP}

RUN --mount=type=cache,target=/usr/local/cargo/registry <<EOF && \
    set -e && \
    touch /app/src/main.rs && \
    cargo build --release && \
    EOF

# Distribute the binary
FROM gcr.io/distroless/cc-debian11 AS release

WORKDIR /dist

COPY --from=builder /app/target/release/sp-security ./sp-security
COPY .env /dist/
CMD ["/dist/sp-security"]