#!/usr/bin/env bash
# Writes a signed APT repository tree from a set of .deb files, one suite per
# distribution release (ci/packages/suites.sh), each .deb in the suite its
# version names:
#
#   <tree>/dists/<suite>/{Release,InRelease,Release.gpg}
#   <tree>/dists/<suite>/main/binary-amd64/Packages{,.gz,.xz}
#   <tree>/pool/<suite>/main/<letter>/<package>/<file>.deb
#   <tree>/validity-rs-archive-keyring.gpg              (bootstrap)
#   <tree>/validity-rs-<suite>.sources                  (bootstrap, per suite)
#   <tree>/validity-rs.sources                          (the trixie one, as
#                                                        first published)
#
#   apt-repo.sh <tree> <signing key id> <public key file> <deb>...
#
# Every suite written must hold validity-daemon and validity-rs-archive-keyring.
# The tree is a function of the .deb files: the publishing workflow rebuilds it
# from the release's packages and the APT test from its own. GNUPGHOME holds
# the signing key (the CI secret holds only the signing subkey; the primary
# key stays offline, see docs/packaging.md). Runs in the Debian build image.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=suites.sh
. "$here/suites.sh"

tree=$1 key=$2 pub=$3; shift 3
packaging=${PACKAGING:-/packaging}
rm -rf "$tree"
mkdir -p "$tree"
declare -A present=()
for deb in "$@"; do
    name=$(dpkg-deb -f "$deb" Package)
    suite=$(suite_of_version "$(dpkg-deb -f "$deb" Version)")
    present[$suite]=1
    dir=$tree/pool/$suite/main/${name:0:1}/$name
    mkdir -p "$dir"
    cp "$deb" "$dir/"
done
cd "$tree"
check=$(mktemp -d)
gpg --homedir "$check" --batch --quiet --import "$pub"
for suite in "${SUITES[@]}"; do
    [ -n "${present[$suite]:-}" ] || continue
    for name in validity-daemon validity-rs-archive-keyring; do
        [ -d "pool/$suite/main/${name:0:1}/$name" ] || { echo "suite $suite: no $name" >&2; exit 1; }
    done
    dist=dists/$suite
    mkdir -p "$dist/main/binary-amd64"
    apt-ftparchive packages "pool/$suite" >"$dist/main/binary-amd64/Packages"
    gzip -9nk "$dist/main/binary-amd64/Packages"
    xz -9k "$dist/main/binary-amd64/Packages"
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=validity-rs \
        -o APT::FTPArchive::Release::Label=validity-rs \
        -o "APT::FTPArchive::Release::Suite=$suite" \
        -o "APT::FTPArchive::Release::Codename=$suite" \
        -o APT::FTPArchive::Release::Architectures=amd64 \
        -o APT::FTPArchive::Release::Components=main \
        -o "APT::FTPArchive::Release::Description=validity-rs packages for $(suite_release "$suite")" \
        release "$dist" >"$dist/Release.tmp"
    mv "$dist/Release.tmp" "$dist/Release"
    gpg --batch --yes --local-user "$key" --digest-algo SHA512 \
        --clearsign --output "$dist/InRelease" "$dist/Release"
    gpg --batch --yes --local-user "$key" --digest-algo SHA512 \
        --armor --detach-sign --output "$dist/Release.gpg" "$dist/Release"
    # Both signatures must verify against the public key users get.
    gpg --homedir "$check" --batch --verify "$dist/InRelease"
    gpg --homedir "$check" --batch --verify "$dist/Release.gpg" "$dist/Release"
    "$here/apt-sources.sh" "$packaging" "$suite" >"validity-rs-$suite.sources"
    cat "$dist/Release"
done
rm -rf "$check"
cp "$pub" validity-rs-archive-keyring.gpg
if [ -n "${present[trixie]:-}" ]; then cp validity-rs-trixie.sources validity-rs.sources; fi
find . -type f | LC_ALL=C sort
