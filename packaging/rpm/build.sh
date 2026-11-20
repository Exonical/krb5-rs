#!/bin/sh
# Build the krb5-rs RPMs from the committed HEAD: packaging/rpm/build.sh [rpmbuild args]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n1)
top=${RPM_TOPDIR:-$root/target/rpmbuild}
mkdir -p "$top/SOURCES" "$top/SPECS"
git -C "$root" archive --format=tar.gz --prefix="krb5-rs-$version/" \
    -o "$top/SOURCES/krb5-rs-$version.tar.gz" HEAD
# The version goes into the spec itself, so the source RPM rebuilds as is.
sed "s/@VERSION@/$version/" "$root/packaging/rpm/krb5-rs.spec" >"$top/SPECS/krb5-rs.spec"
rpmbuild -ba --define "_topdir $top" "$@" "$top/SPECS/krb5-rs.spec"
