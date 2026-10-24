#!/usr/bin/env bash
# The APT test's repositories (ci/packages/run.sh apt), in the Debian build
# image without network. A throwaway key is made here, laid out like the real
# one (an ed25519 primary key that only certifies, an ed25519 subkey that
# signs), and thrown away with the container; the real key never enters CI
# tests. Writes, under <out>/apt:
#   keyring/   validity-rs-archive-keyring with the throwaway key
#   v1/        repository with validity-daemon <version>-1
#   v2/        the next publication: validity-daemon <version>-2
# fingerprint-settings is added to both when <out>/extra holds its .deb.
#   apt-test-repo.sh <out>
set -euo pipefail

out=$1
export GNUPGHOME
GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key \
    'validity-rs throwaway test key (CI only) <test@invalid>' ed25519 cert 1d
primary=$(gpg --with-colons --list-keys | awk -F: '/^fpr:/ { print $10; exit }')
gpg --batch --passphrase '' --quick-add-key "$primary" ed25519 sign 1d
sub=$(gpg --with-colons --list-keys | awk -F: '/^fpr:/ { f = $10 } END { print f }')
gpg --export "$primary" >"$out/apt-test-key.gpg"
echo "test key: primary $primary, signing subkey $sub"

rm -rf "$out/apt"
/ci/build-keyring.sh "$out/apt-test-key.gpg" "$out/apt/keyring"
keyring=$(ls "$out"/apt/keyring/validity-rs-archive-keyring_*_all.deb)
extra=()
if ls "$out"/extra/fingerprint-settings_*.deb >/dev/null 2>&1; then
    extra=("$out"/extra/fingerprint-settings_*.deb)
fi
# The subkey, as the publishing workflow signs ("!": exactly this subkey).
/ci/apt-repo.sh "$out/apt/v1" "$sub!" "$out/apt-test-key.gpg" \
    "$out"/debian/validity-daemon_*-1_amd64.deb "$keyring" "${extra[@]}"
/ci/apt-repo.sh "$out/apt/v2" "$sub!" "$out/apt-test-key.gpg" \
    "$out"/apt-next/validity-daemon_*-2_amd64.deb "$keyring" "${extra[@]}"
gpgconf --kill gpg-agent
rm -rf "$GNUPGHOME"
