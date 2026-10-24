#!/usr/bin/env bash
# Builds validity-rs-archive-keyring_<version>_all.deb: the repository's public
# key in its own keyring, the APT source and the unattended-upgrades snippet
# (packaging/apt), and lints it. Runs in the Debian build image.
#   build-keyring.sh <public key (binary OpenPGP)> <output dir> [packaging dir]
# The release uses packaging/apt/validity-rs-archive-keyring.gpg; the APT test
# passes its throwaway key.
set -euo pipefail

key=$1 out=$2 apt=${3:-${PACKAGING:-/packaging}}/apt
: "${SOURCE_DATE_EPOCH:?}"
version=$(sed -n '1s/^validity-rs-archive-keyring (\([^)]*\)).*/\1/p' "$apt/keyring/changelog")
pkg=validity-rs-archive-keyring
tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT

install -D -m 0644 "$key" "$tree/usr/share/keyrings/$pkg.gpg"
install -D -m 0644 "$apt/validity-rs.sources" "$tree/etc/apt/sources.list.d/validity-rs.sources"
install -D -m 0644 "$apt/50validity-rs" "$tree/etc/apt/apt.conf.d/50validity-rs"
install -D -m 0644 "$apt/keyring/copyright" "$tree/usr/share/doc/$pkg/copyright"
install -D -m 0644 "$apt/keyring/lintian-overrides" "$tree/usr/share/lintian/overrides/$pkg"
gzip -9n <"$apt/keyring/changelog" >"$tree/usr/share/doc/$pkg/changelog.gz"
chmod 0644 "$tree/usr/share/doc/$pkg/changelog.gz"
# The key must be a binary keyring with exactly one primary key.
[ "$(gpg --show-keys --with-colons "$key" | grep -c '^pub:')" = 1 ] || {
    echo "$key: expected exactly one public key" >&2
    exit 1
}

mkdir -p "$tree/DEBIAN"
sed "s/@VERSION@/$version/" "$apt/keyring/control" >"$tree/DEBIAN/control"
printf '%s\n' /etc/apt/apt.conf.d/50validity-rs /etc/apt/sources.list.d/validity-rs.sources \
    >"$tree/DEBIAN/conffiles"
echo "Installed-Size: $(du -sk --exclude=DEBIAN "$tree" | cut -f1)" >>"$tree/DEBIAN/control"
(cd "$tree" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' | LC_ALL=C sort -z \
    | xargs -0 md5sum >DEBIAN/md5sums)
chmod 0644 "$tree"/DEBIAN/*
find "$tree" -type d -exec chmod 0755 {} +
find "$tree" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$out"
deb=$out/${pkg}_${version}_all.deb
dpkg-deb --root-owner-group -Zxz --build "$tree" "$deb"
dpkg-deb --info "$deb"
dpkg-deb --contents "$deb"
chmod -R a+rX "$out"
runuser -u nobody -- lintian --fail-on error,warning --display-info --tag-display-limit 0 "$deb"
echo "lintian: clean"
