#!/usr/bin/env bash
# The APT repository as a user meets it, in a clean Debian 13 or Ubuntu with
# systemd (ci/packages/run.sh apt[-<suite>]). The repository is served over HTTP
# by another container (apt-repo:8000); the distribution's own packages come
# from its mirrors.
#
#   apt-client.sh install <suite>   bootstrap with the keyring package, apt update,
#                           apt install validity-daemon (and fingerprint-settings
#                           when the repository has it), unattended-upgrades
#   apt-client.sh upgrade <suite>   after the next publication: unattended-upgrade
#                           in dry-run, then for real; the upgrade must happen
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

REPO=http://apt-repo:8000
SUITE=${2:?suite}
# shellcheck source=suites.sh
. "$(dirname "$0")/suites.sh"
SUFFIX=$(suite_suffix "$SUITE")
SOURCES=/etc/apt/sources.list.d/validity-rs.sources
# The vendor download is not under test here (ci/packages/cycle.sh covers it):
# unreachable, so the run never depends on Lenovo's server.
export VALIDITY_VENDOR_URL=http://127.0.0.1:9/nz3gf07w.exe

say() { printf '\n\033[1m-- %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
# eventually <pattern> <command...>: like expect, retried for up to 10 s.
# Right after it starts, the daemon lists the device while it probes for it,
# so a client asking then gets an error before the settled answer.
eventually() {
    local pat=$1 out i; shift
    for i in $(seq 1 20); do
        out=$("$@" 2>&1) || true
        printf '%s\n' "$out" | grep -qE "$pat" && break
        sleep 0.5
    done
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\n' "$out" | grep -qE "$pat" || fail "expected /$pat/ within 10 s from: $*"
}
expect() {
    local pat=$1 out; shift
    out=$("$@" 2>&1) || true
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\n' "$out" | grep -qE "$pat" || fail "expected /$pat/ from: $*"
}
version() { dpkg-query -W -f '${Version}' "$1" 2>/dev/null; }
main_pid() { systemctl show -p MainPID --value validity-daemon.service; }

phase_install() {
    say "boot"
    for _ in $(seq 1 150); do
        systemctl is-system-running --wait 2>/dev/null | grep -qE '^(running|degraded)$' && break
        sleep 0.2
    done
    echo "    $(systemctl is-system-running)"

    say "bootstrap: the key and this release's source, as the repository serves them"
    # As a user does (docs/packaging.md): the suite named by os-release.
    . /etc/os-release
    [ "$VERSION_CODENAME" = "$SUITE" ] || fail "this is $VERSION_CODENAME, not $SUITE"

    apt-get update -qq
    apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null
    curl -fsS -o /tmp/validity-rs-archive-keyring.gpg "$REPO/validity-rs-archive-keyring.gpg"
    install -m 0644 /tmp/validity-rs-archive-keyring.gpg /usr/share/keyrings/
    curl -fsS -o "$SOURCES" "$REPO/validity-rs-$VERSION_CODENAME.sources"
    cp "$SOURCES" /tmp/sources.bootstrap
    expect "^Suites: $SUITE\$" cat "$SOURCES"

    say "the keyring package over the bootstrap files"
    # The suite's own build, as apt would fetch it. Its two files are the ones
    # just written, byte for byte: dpkg takes them over without a question.
    keyring=$(curl -fsS "$REPO/dists/$SUITE/main/binary-amd64/Packages" \
        | awk '/^Package: validity-rs-archive-keyring/ { p = 1 } p && /^Filename:/ { print $2; exit }')
    [ -n "$keyring" ] || fail "no keyring package in suite $SUITE"
    curl -fsS -o /tmp/keyring.deb "$REPO/$keyring"
    apt-get install -y /tmp/keyring.deb </dev/null
    cmp "$SOURCES" /tmp/sources.bootstrap || fail "the packaged source differs from the bootstrap one"
    expect 'Signed-By: /usr/share/keyrings/validity-rs-archive-keyring.gpg' cat "$SOURCES"
    expect 'origin=validity-rs,codename=\$\{distro_codename\},label=validity-rs' \
        cat /etc/apt/apt.conf.d/50validity-rs
    cmp /usr/share/keyrings/validity-rs-archive-keyring.gpg /tmp/validity-rs-archive-keyring.gpg \
        || fail "the packaged key differs from the published one"
    # Test only: the repository is on the local server, not on GitHub Pages.
    sed -i "s|^URIs: .*|URIs: $REPO|" "$SOURCES"

    say "the key is trusted for this repository only"
    cp "$SOURCES" /tmp/sources.good
    distro_key=
    for k in /usr/share/keyrings/debian-archive-keyring.pgp /usr/share/keyrings/ubuntu-archive-keyring.gpg; do
        [ -f "$k" ] && distro_key=$k && break
    done
    [ -n "$distro_key" ] || fail "no distribution archive key"
    sed -i "s|^Signed-By: .*|Signed-By: $distro_key|" "$SOURCES"
    expect "NO_PUBKEY|not signed|is not signed|Missing key|could not be verified|no valid OpenPGP" apt-get update
    cp /tmp/sources.good "$SOURCES"

    say "apt update"
    out=$(apt-get update 2>&1)
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\n' "$out" | grep -E '^(W|E):' && fail "apt update warned"
    expect "$REPO $SUITE/main amd64 Packages" apt-cache policy validity-daemon
    expect "o=validity-rs,a=$SUITE,n=$SUITE,l=validity-rs,c=main" apt-cache policy

    say "apt install validity-daemon"
    apt-get install -y --no-install-recommends validity-daemon
    v=$(version validity-daemon)
    echo "    validity-daemon $v"
    case "$v" in *-1"$SUFFIX") ;; *) fail "expected revision 1$SUFFIX, got $v" ;; esac
    if apt-cache show fingerprint-settings >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends fingerprint-settings
        echo "    fingerprint-settings $(version fingerprint-settings)"
    else
        echo "    NOTICE: no fingerprint-settings package in this repository (its .deb was not built here); skipped"
    fi
    eventually 'No devices available' fprintd-list root
    expect '^active$' systemctl is-active validity-daemon.service
    main_pid >/tmp/pid.before

    say "unattended-upgrades, with the repository's origin"
    apt-get install -y -qq --no-install-recommends unattended-upgrades >/dev/null
    expect 'origin=validity-rs' apt-config dump Unattended-Upgrade::Origins-Pattern
}

phase_upgrade() {
    say "next publication: apt update sees it"
    apt-get update -qq
    expect "Candidate: .*-2$SUFFIX" apt-cache policy validity-daemon
    v=$(version validity-daemon)

    say "unattended-upgrade --dry-run"
    expect 'Packages that will be upgraded: .*validity-daemon' unattended-upgrade --dry-run -d
    [ "$(version validity-daemon)" = "$v" ] || fail "the dry run changed the package"

    say "unattended-upgrade"
    expect 'Packages that will be upgraded: .*validity-daemon' unattended-upgrade -d
    v2=$(version validity-daemon)
    echo "    validity-daemon $v -> $v2"
    case "$v2" in *-2"$SUFFIX") ;; *) fail "not upgraded: $v2" ;; esac
    expect 'validity-daemon' tail -20 /var/log/unattended-upgrades/unattended-upgrades.log

    say "the running daemon was restarted on the new version"
    expect '^active$' systemctl is-active validity-daemon.service
    [ "$(main_pid)" != "$(cat /tmp/pid.before)" ] || fail "the daemon was not restarted"
    eventually 'No devices available' fprintd-list root
    say "apt: OK"
}

"phase_$1"
