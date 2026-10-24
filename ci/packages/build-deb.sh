#!/usr/bin/env bash
# Builds the .deb from the vendored source tarball and lints it, inside the
# Debian build image with no network (ci/packages/run.sh debian).
#   build-deb.sh <tarball> <output dir> [deb revision]
set -euo pipefail

tarball=$1 out=$2 revision=${3:-}
: "${SOURCE_DATE_EPOCH:?}"
name=$(basename "$tarball" .tar.gz)
rm -rf "/build/$name"
tar -xzf "$tarball" -C /build
cd "/build/$name"

cargo build --release --offline --locked -p validity-daemon -p validity-vendor
mkdir -p "$out"
cargo deb -p validity-daemon --no-build --offline --locked \
    ${revision:+--deb-revision "$revision"} --output "$out"

deb=$(ls "$out"/validity-daemon_*.deb)
# cargo-deb writes no md5sums; dpkg --verify and debsums need them. Added as
# dh_md5sums does, and the package rebuilt with dpkg-deb (same contents,
# mtimes clamped to SOURCE_DATE_EPOCH).
tree=$(mktemp -d)
dpkg-deb --raw-extract "$deb" "$tree"
(cd "$tree" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | LC_ALL=C sort -z \
    | xargs -0 md5sum >DEBIAN/md5sums)
chmod 0644 "$tree/DEBIAN/md5sums"
dpkg-deb --root-owner-group -Zxz --build "$tree" "$deb"
rm -rf "$tree"
dpkg-deb --info "$deb"
dpkg-deb --contents "$deb"
# Lintian clean: any error or warning fails; info tags are shown for review.
chmod -R a+rX "$out"
runuser -u nobody -- lintian --fail-on error,warning --display-info --tag-display-limit 0 "$deb"
echo "lintian: clean"
