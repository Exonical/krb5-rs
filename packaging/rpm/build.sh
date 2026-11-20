#!/bin/sh
# Build the krb5-rs RPMs from the committed HEAD: packaging/rpm/build.sh [rpmbuild args]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n1)
top=${RPM_TOPDIR:-$root/target/rpmbuild}
mkdir -p "$top/SOURCES"
git -C "$root" archive --format=tar.gz --prefix="krb5-rs-$version/" \
    -o "$top/SOURCES/krb5-rs-$version.tar.gz" HEAD
rpmbuild -ba --define "_topdir $top" --define "pkg_version $version" "$@" \
    "$root/packaging/rpm/krb5-rs.spec"
