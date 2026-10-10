# krb5-rs KDC: static musl binaries in a distroless nonroot image.
#
# Build (context = repository root):
#   podman build -f deploy/docker/Dockerfile -t krb5-rs-kdc .
#
# The server must listen on an unprivileged port: the image runs as uid 65532
# and cannot bind 88. Use kdc_ports = 8888 / kdc_tcp_ports = 8888 in kdc.conf
# (or --listen) and map the service port 88 to 8888 outside the container.
# No HEALTHCHECK is defined; orchestrators probe the listening port.

# rust:1.99.0-bookworm (index digest)
FROM docker.io/library/rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build

ARG TARGET=x86_64-unknown-linux-musl
RUN rustup target add "$TARGET"

WORKDIR /src
COPY Cargo.toml Cargo.lock README.md LICENSE ./
COPY src ./src
COPY examples ./examples
COPY crates ./crates

# Everything is pure Rust, so the self-contained musl toolchain is enough.
ENV RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols"
RUN cargo build --locked --release -p krb5-rs-kdc --target "$TARGET" \
 && mkdir /out \
 && cp "target/$TARGET/release/krb5-rs-kdc" "target/$TARGET/release/krb5-rs-kdb" /out/

# gcr.io/distroless/static-debian12:nonroot (index digest)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="krb5-rs-kdc" \
      org.opencontainers.image.description="Pure Rust Kerberos V5 KDC and database administration tool" \
      org.opencontainers.image.source="https://github.com/Exonical/krb5-rs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/krb5-rs-kdc /out/krb5-rs-kdb /usr/local/bin/

USER 65532:65532
EXPOSE 8888/udp 8888/tcp
ENTRYPOINT ["/usr/local/bin/krb5-rs-kdc"]
