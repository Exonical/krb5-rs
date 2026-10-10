# MIT krb5 1.22.2 built from the official release tarball, for the live
# interop tests. No distro krb5 packages are installed, so nothing can
# silently use another version.
FROM ubuntu:24.04

ARG KRB5_VERSION=1.22.2
ARG KRB5_URL=https://kerberos.org/dist/krb5/1.22/krb5-1.22.2.tar.gz
# Detached signature (C449 3CB7 39F4 A89F 9852  CBC2 0CBA 0857 5F83 72DF,
# Greg Hudson) checked when the pin was chosen: krb5-1.22.2.tar.gz.asc.
ARG KRB5_SHA256=3243ffbc8ea4d4ac22ddc7dd2a1dc54c57874c40648b60ff97009763554eaf13
ARG GSSAPI_VERSION=1.9.0

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      build-essential bison flex ca-certificates pkg-config \
      libssl-dev libkeyutils-dev python3 python3-dev python3-pip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" "$KRB5_URL" /tmp/krb5.tar.gz; \
    echo "$KRB5_SHA256  /tmp/krb5.tar.gz" | sha256sum -c -; \
    mkdir /tmp/krb5-src; \
    tar -xzf /tmp/krb5.tar.gz -C /tmp/krb5-src --strip-components=1; \
    cd /tmp/krb5-src/src; \
    ./configure --prefix=/usr/local --sysconfdir=/etc --localstatedir=/var \
        --without-ldap --without-tcl --without-libedit --disable-nls; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    rm -rf /tmp/krb5-src /tmp/krb5.tar.gz

# python-gssapi must link the krb5 built above, not a distro copy.
RUN set -eux; \
    pip3 install --break-system-packages --no-cache-dir --no-binary gssapi \
        "gssapi==${GSSAPI_VERSION}"

RUN set -eux; \
    test "$(krb5-config --version)" = "Kerberos 5 release ${KRB5_VERSION}"; \
    test "$(command -v krb5kdc)" = /usr/local/sbin/krb5kdc; \
    python3 -c "import gssapi.raw, sys; maps = open('/proc/self/maps').read(); libs = sorted({l.split()[-1] for l in maps.splitlines() if 'libgssapi_krb5' in l}); print(libs); sys.exit(0 if libs and all(p.startswith('/usr/local/lib/') for p in libs) else 1)"; \
    if dpkg -l | grep -E "^ii +(libkrb5-3|krb5-)"; then exit 1; fi
