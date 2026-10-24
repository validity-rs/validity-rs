#!/usr/bin/env bash
# The published APT repository tree (.github/workflows/release.yml, apt job),
# in the Debian build image without network: imports the signing subkey from
# APT_SIGNING_KEY (an armored export holding only the subkey, see
# docs/packaging.md) into a throwaway GnuPG home, checks it belongs to the
# published key, and writes the tree from every .deb in <debs dir>.
#   apt-sign-tree.sh <debs dir> <tree>
set -euo pipefail

debs=$1 tree=$2
: "${APT_SIGNING_KEY:?the APT signing subkey (secret APT_SIGNING_KEY)}"
pub=${PACKAGING:-/packaging}/apt/validity-rs-archive-keyring.gpg
export GNUPGHOME
GNUPGHOME=$(mktemp -d)
trap 'gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"' EXIT
printf '%s\n' "$APT_SIGNING_KEY" | gpg --batch --quiet --import
# The one secret signing subkey, and the primary key it hangs from.
sub=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "ssb" && $12 ~ /s/ { s = 1; next } s && $1 == "fpr" { print $10; exit }')
primary=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
expected=$(gpg --batch --with-colons --show-keys "$pub" | awk -F: '$1 == "fpr" { print $10; exit }')
[ -n "$sub" ] || { echo "APT_SIGNING_KEY holds no signing subkey" >&2; exit 1; }
[ "$primary" = "$expected" ] || {
    echo "APT_SIGNING_KEY belongs to $primary, not to the published key $expected" >&2
    exit 1
}
echo "signing with subkey $sub of $primary"
mapfile -t files < <(find "$debs" -name '*.deb' | LC_ALL=C sort)
[ ${#files[@]} -gt 0 ] || { echo "no .deb in $debs" >&2; exit 1; }
/ci/apt-repo.sh "$tree" "$sub!" "$pub" "${files[@]}"
# GitHub Pages: serve the tree as it is (no Jekyll).
touch "$tree/.nojekyll"
