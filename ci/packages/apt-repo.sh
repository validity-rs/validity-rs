#!/usr/bin/env bash
# Writes a signed APT repository tree from a set of .deb files:
#
#   <tree>/dists/trixie/{Release,InRelease,Release.gpg}
#   <tree>/dists/trixie/main/binary-amd64/Packages{,.gz,.xz}
#   <tree>/pool/main/<letter>/<package>/<file>.deb
#   <tree>/validity-rs-archive-keyring.gpg, validity-rs.sources (bootstrap)
#
#   apt-repo.sh <tree> <signing key id> <public key file> <deb>...
#
# The tree is a function of the .deb files: the publishing workflow rebuilds it
# from the release's packages and the APT test from its own. GNUPGHOME holds
# the signing key (the CI secret holds only the signing subkey; the primary
# key stays offline, see docs/packaging.md). Runs in the Debian build image.
set -euo pipefail

tree=$1 key=$2 pub=$3; shift 3
SUITE=trixie
rm -rf "$tree"
mkdir -p "$tree/dists/$SUITE/main/binary-amd64"
for deb in "$@"; do
    name=$(dpkg-deb -f "$deb" Package)
    dir=$tree/pool/main/${name:0:1}/$name
    mkdir -p "$dir"
    cp "$deb" "$dir/"
done
cd "$tree"
apt-ftparchive packages pool >"dists/$SUITE/main/binary-amd64/Packages"
gzip -9nk "dists/$SUITE/main/binary-amd64/Packages"
xz -9k "dists/$SUITE/main/binary-amd64/Packages"
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=validity-rs \
    -o APT::FTPArchive::Release::Label=validity-rs \
    -o APT::FTPArchive::Release::Suite=$SUITE \
    -o APT::FTPArchive::Release::Codename=$SUITE \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    -o "APT::FTPArchive::Release::Description=validity-rs packages for Debian 13" \
    release "dists/$SUITE" >"dists/$SUITE/Release.tmp"
mv "dists/$SUITE/Release.tmp" "dists/$SUITE/Release"
gpg --batch --yes --local-user "$key" --digest-algo SHA512 \
    --clearsign --output "dists/$SUITE/InRelease" "dists/$SUITE/Release"
gpg --batch --yes --local-user "$key" --digest-algo SHA512 \
    --armor --detach-sign --output "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
# Both signatures must verify against the public key users get.
check=$(mktemp -d)
gpg --homedir "$check" --batch --quiet --import "$pub"
gpg --homedir "$check" --batch --verify "dists/$SUITE/InRelease"
gpg --homedir "$check" --batch --verify "dists/$SUITE/Release.gpg" "dists/$SUITE/Release"
rm -rf "$check"
cp "$pub" validity-rs-archive-keyring.gpg
cp "${PACKAGING:-/packaging}/apt/validity-rs.sources" validity-rs.sources
cat "dists/$SUITE/Release"
find . -type f | LC_ALL=C sort
