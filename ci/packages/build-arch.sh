#!/usr/bin/env bash
# Builds the Arch package with packaging/archlinux/PKGBUILD from the vendored
# source tarball, pinned by its sha256, and lints it with namcap, inside the
# Arch build image with no network (ci/packages/run.sh archlinux). Also writes
# the PKGBUILD for the AUR: the release URL with this tarball's sha256.
#   build-arch.sh <tarball> <output dir>
set -euo pipefail

tarball=$1 out=$2
: "${SOURCE_DATE_EPOCH:?}"
name=$(basename "$tarball" .tar.gz)
version=${name#validity-rs-}
work=/home/builder/pkg
rm -rf "$work"
mkdir -p "$work"
tar -xzf "$tarball" -C "$work" --strip-components=3 \
    "$name/packaging/archlinux/PKGBUILD" "$name/packaging/archlinux/validity-daemon.install"
grep -qE "^pkgver=$version\$" "$work/PKGBUILD" || {
    echo "the PKGBUILD's pkgver is not $version (Cargo.toml)" >&2
    exit 1
}
sum=$(sha256sum "$tarball" | cut -d' ' -f1)
mkdir -p "$out"
# For the AUR: the published tarball, pinned.
sed "s|^sha256sums=.*|sha256sums=('$sum')|" "$work/PKGBUILD" >"$out/PKGBUILD"
cp "$work/validity-daemon.install" "$out/"
# The AUR also wants .SRCINFO, generated from that PKGBUILD.
chown -R builder: "$out" "$work"
runuser -u builder -- sh -c "cd '$out' && makepkg --printsrcinfo >.SRCINFO"
# Here: the same tarball, from disk.
cp "$tarball" "$work/"
sed -i -e "s|^source=.*|source=(\"validity-rs-\$pkgver.tar.gz\")|" \
    -e "s|^sha256sums=.*|sha256sums=('$sum')|" "$work/PKGBUILD"
chown -R builder: "$work"
# Only what is set: cargo rejects an empty CARGO_BUILD_JOBS.
vars=(SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" PKGDEST="$work/out")
[ -n "${CARGO_BUILD_JOBS:-}" ] && vars+=(CARGO_BUILD_JOBS="$CARGO_BUILD_JOBS")
runuser -u builder -- env "${vars[@]}" sh -c "cd '$work' && makepkg --nodeps --noconfirm --cleanbuild"
cp "$work"/out/validity-daemon-"$version"-*-x86_64.pkg.tar.zst "$out/"
pkg=$(ls "$out"/validity-daemon-"$version"-*-x86_64.pkg.tar.zst)
pacman -Qip "$pkg"
pacman -Qlp "$pkg"
# namcap: any error fails; warnings are shown.
lint=$(namcap "$out/PKGBUILD" "$pkg" 2>&1 || true)
printf '%s\n' "$lint"
if printf '%s\n' "$lint" | grep -q ' E: '; then
    echo "namcap: errors" >&2
    exit 1
fi
echo "namcap: no errors"
