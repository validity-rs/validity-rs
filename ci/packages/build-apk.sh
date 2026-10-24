#!/usr/bin/env bash
# Builds the Alpine package with packaging/alpine/APKBUILD from the vendored
# source tarball and lints the APKBUILD, inside the Alpine build image with no
# network (ci/packages/run.sh alpine). abuild runs as an unprivileged user with
# a throwaway signing key (the cycle installs with --allow-untrusted). Also
# writes the APKBUILD with its sha512sums, as aports would take it.
#   build-apk.sh <tarball> <output dir>
set -euo pipefail

tarball=$1 out=$2
: "${SOURCE_DATE_EPOCH:?}"
name=$(basename "$tarball" .tar.gz)
version=${name#validity-rs-}
work=/home/builder/aports/validity-daemon
rm -rf /home/builder/aports /home/builder/packages
mkdir -p "$work"
tar -xzf "$tarball" -C "$work" --strip-components=3 \
    "$name/packaging/alpine/APKBUILD" "$name/packaging/alpine/validity-daemon.initd" \
    "$name/packaging/alpine/validity-daemon.post-install" "$name/packaging/alpine/validity-daemon.post-upgrade" \
    "$name/packaging/alpine/validity-daemon.pre-deinstall" "$name/packaging/alpine/validity-daemon.post-deinstall"
grep -qE "^pkgver=$version\$" "$work/APKBUILD" || {
    echo "the APKBUILD's pkgver is not $version (Cargo.toml)" >&2
    exit 1
}
# The source is the published tarball; here it is already on disk, where
# abuild looks before downloading.
cp "$tarball" "$work/"
chown -R builder: /home/builder
as_builder() {
    runuser -u builder -- env HOME=/home/builder PATH="$PATH" \
        RUSTUP_HOME="${RUSTUP_HOME:-}" CARGO_HOME=/home/builder/.cargo \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-}" \
        SRCDEST="$work" REPODEST=/home/builder/packages sh -c "cd '$work' && $*"
}
as_builder abuild-keygen -a -n -q
as_builder abuild checksum
as_builder abuild -d
mkdir -p "$out"
cp "$work/APKBUILD" "$out/APKBUILD"
find /home/builder/packages -name '*.apk' -exec cp {} "$out/" \;
ls -l "$out"
pkg=$(ls "$out"/validity-daemon-"$version"-r*.apk)
tar -tzif "$pkg" | sort
# apkbuild-lint (atools): any finding fails.
apkbuild-lint "$work/APKBUILD"
echo "apkbuild-lint: clean"
