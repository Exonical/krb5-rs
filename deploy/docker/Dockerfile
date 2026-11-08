# krb5-rs KDC: dynamically linked glibc binaries in a distroless nonroot
# image. Like MIT's builds, krb5-rs-kadmind can then dlopen kadm5_auth
# modules ([plugins] kadm5_auth module = name:path); static musl cannot.
#
# Build (context = repository root):
#   podman build -f deploy/docker/Dockerfile -t krb5-rs-kdc .
#   podman build --build-arg FEATURES=cockroach -f deploy/docker/Dockerfile \
#     -t krb5-rs-kdc:cockroach .
#
# The server must listen on an unprivileged port: the image runs as uid 65532
# and cannot bind 88. Use kdc_ports = 8888 / kdc_tcp_ports = 8888 in kdc.conf
# (or --listen) and map the service port 88 to 8888 outside the container.
# No HEALTHCHECK is defined; orchestrators probe the listening port.

ARG FEATURES=""
ARG DESCRIPTION="Pure Rust Kerberos V5 KDC and database administration tool"

# rust:1.99.0-bookworm (index digest)
FROM docker.io/library/rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build

ARG FEATURES
RUN if [ -n "$FEATURES" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends cmake \
      && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /src
COPY Cargo.toml Cargo.lock README.md LICENSE ./
COPY src ./src
COPY examples ./examples
COPY crates ./crates
COPY vendor ./vendor

# The default build includes the klmdb module (LMDB C library).
# FEATURES=cockroach additionally enables rustls/aws-lc-rs and Turso's
# simsimd. Binaries link glibc (bookworm, as in the runtime image)
# dynamically.
ENV RUSTFLAGS="-C strip=symbols"
RUN cargo build --locked --release -p krb5-rs-kdc ${FEATURES:+--features "$FEATURES"} \
 && mkdir -p /out/data \
 && cp target/release/krb5-rs-kdc target/release/krb5-rs-kdb \
      target/release/krb5-rs-kprop target/release/krb5-rs-kpropd \
      target/release/krb5-rs-kproplog target/release/krb5-rs-kadmind /out/

# gcr.io/distroless/cc-debian12:nonroot (index digest): glibc, libgcc_s and
# libstdc++ for dynamically linked binaries.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG DESCRIPTION

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="krb5-rs-kdc" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.source="https://github.com/Exonical/krb5-rs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/krb5-rs-kdc /out/krb5-rs-kdb /out/krb5-rs-kprop /out/krb5-rs-kpropd /out/krb5-rs-kproplog /out/krb5-rs-kadmind /usr/local/bin/
# Pre-owned data directory: new volumes mounted here inherit uid 65532.
COPY --from=build --chown=65532:65532 /out/data /var/lib/krb5-rs

USER 65532:65532
EXPOSE 8888/udp 8888/tcp
ENTRYPOINT ["/usr/local/bin/krb5-rs-kdc"]
