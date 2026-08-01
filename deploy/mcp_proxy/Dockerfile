FROM rust:1-bookworm AS build
WORKDIR /workspace
COPY . .
RUN cargo build --release -p velvet-rope-proxy

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 velvet \
    && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /var/lib/velvet velvet
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
COPY --from=build /workspace/target/release/velvet-rope-proxy /usr/local/bin/velvet-rope-proxy
USER velvet
WORKDIR /var/lib/velvet
ENTRYPOINT ["/usr/local/bin/velvet-rope-proxy"]
