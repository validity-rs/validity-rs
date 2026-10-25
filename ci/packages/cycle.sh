#!/usr/bin/env bash
# The package cycle, run as root in a fresh test container of the distro
# (ci/packages/run.sh <distro>): install the package, check what it installed,
# start the daemon on the emulated sensor and query it with fprintd's own
# client, check D-Bus activation, remove the package, then check that fprintd
# has its activation back and that nothing is left behind.
#
#   cycle.sh <debian|fedora|archlinux|alpine> <package file>
#
# VENDOR_ONLINE=1 also downloads Lenovo's real package with validity-vendor.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

distro=$1 pkg=$2
FPRINT_SERVICE=/usr/share/dbus-1/system-services/net.reactivated.Fprint.service
# During the installation Lenovo's server is unreachable on purpose
# (download.lenovo.com -> 127.0.0.1 in /etc/hosts, whatever environment the
# package manager gives its scripts): the cycle never depends on it, and the
# package must install anyway and say how to finish.
offline() { cp /etc/hosts /tmp/hosts.orig && echo '127.0.0.1 download.lenovo.com' >>/etc/hosts; }
online() { cat /tmp/hosts.orig >/etc/hosts; }

say() { printf '\n\033[1m-- %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
# expect <pattern> <command...>: runs it, shows its output, fails unless the
# pattern (extended regex) matches.
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
wait_for() {
    local i
    for i in $(seq 1 150); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
    fail "timed out: $*"
}
has_owner() {
    dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.NameHasOwner "string:$1" | grep -q 'boolean true'
}
no_owner() { ! has_owner "$1"; }
# Whether a process runs this executable (no procps in every image).
running() {
    local c
    for c in /proc/[0-9]*/cmdline; do
        tr '\0' ' ' <"$c" 2>/dev/null | grep -q "^$1" && return 0
    done
    return 1
}
# The command line of the process owning a bus name.
owner_cmdline() {
    local pid
    pid=$(dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetConnectionUnixProcessID "string:$1" | awk '/uint32/ { print $2 }')
    tr '\0' ' ' <"/proc/$pid/cmdline"
}

# What the cycle compares before and after: every path outside the volatile
# places with its type and mode, and the content hash of every regular file.
SKIP=(/proc /sys /dev /run /tmp /var/tmp /var/log /var/cache /var/lib/apt /var/lib/dnf
    /var/lib/rpm /usr/lib/sysimage/rpm /usr/lib/sysimage/libdnf5 /var/lib/pacman /lib/apk/db /etc/apk/world
    /var/lib/systemd /var/lib/dpkg/status /var/lib/dpkg/status-old /var/lib/dpkg/available
    /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/dpkg/triggers
    /var/lib/dpkg/diversions-old /etc/hosts /etc/ld.so.cache /ci /out /root/.cache /var/lib/fprint)
snapshot() {
    local prune=() p
    for p in "${SKIP[@]}"; do prune+=(-path "$p" -o); done
    prune+=(-false)
    {
        find / -xdev \( "${prune[@]}" \) -prune -o -printf '%y %m %p\n'
        find / -xdev \( "${prune[@]}" \) -prune -o -type f -print0 | xargs -0 -r sha256sum
    } | LC_ALL=C sort
}

# Distro specifics: install, remove, the package's file list, the init system.
case "$distro" in
    debian)
        install_pkg() { apt-get install -y --no-install-recommends "$pkg"; }
        remove_pkg() { apt-get purge -y validity-daemon; }
        pkg_files() { dpkg -L validity-daemon; }
        installed() { dpkg-query -W -f '${Status}' validity-daemon 2>/dev/null | grep -q 'install ok installed'; }
        init=systemd daemon=/usr/libexec/validity-daemon
        ;;
    fedora)
        install_pkg() { dnf install -y --setopt=install_weak_deps=False "$pkg"; }
        remove_pkg() { dnf remove -y validity-daemon; }
        pkg_files() { rpm -ql validity-daemon; }
        installed() { rpm -q validity-daemon; }
        init=systemd daemon=/usr/libexec/validity-daemon
        ;;
    archlinux)
        install_pkg() { pacman -U --noconfirm "$pkg"; }
        remove_pkg() { pacman -Rns --noconfirm validity-daemon; }
        pkg_files() { pacman -Qlq validity-daemon; }
        installed() { pacman -Q validity-daemon; }
        init=systemd daemon=/usr/lib/validity-daemon/validity-daemon
        ;;
    alpine)
        # abuild splits the OpenRC script and the documentation into
        # subpackages, built beside the main one.
        subpkgs() { local d; d=$(dirname "$pkg"); ls "$d"/validity-daemon-openrc-*.apk "$d"/validity-daemon-doc-*.apk; }
        install_pkg() { apk add --no-network --allow-untrusted "$pkg" $(subpkgs); }
        remove_pkg() { apk del validity-daemon validity-daemon-openrc validity-daemon-doc; }
        pkg_files() { apk info -L validity-daemon | sed -n 's|^\([^ ]\)|/\1|p' | grep -v ' contains:'; }
        installed() { apk info -e validity-daemon; }
        init=openrc daemon=/usr/libexec/validity-daemon
        ;;
    *) fail "unknown distro $distro" ;;
esac

say "system up ($init)"
if [ "$init" = systemd ]; then
    # The boot is finished; "degraded" (a unit that needs real hardware) is
    # fine here. The first calls may come before systemd's own bus is up.
    wait_for sh -c 'systemctl is-system-running --wait | grep -qE "^(running|degraded)$"'
    echo "    $(systemctl is-system-running)"
    wait_for test -S /run/dbus/system_bus_socket
else
    # OpenRC in a container: the D-Bus system bus as a service.
    mkdir -p /run/openrc && touch /run/openrc/softlevel
    rc-service dbus start
    wait_for test -S /run/dbus/system_bus_socket
fi
FPRINTD_EXEC='Exec=/usr/lib(exec)?/fprintd'
expect "$FPRINTD_EXEC" cat "$FPRINT_SERVICE"
before=$(mktemp)
snapshot >"$before"
# Debian only: pam-auth-update and its common-* files.
if [ "$distro" = debian ]; then cp /etc/pam.d/common-auth /tmp/common-auth.before; fi

say "install $(basename "$pkg") (Lenovo's server unreachable on purpose)"
offline
expect "validity-vendor: cannot reach https://download.lenovo.com/.*offline" install_pkg
online
installed || fail "not installed"

say "installed files"
pkg_files | sed 's/^/    /'
for f in "$daemon" /usr/share/dbus-1/system.d/validity-daemon.conf; do
    test -f "$f" || fail "missing $f"
done
command -v validity-vendor >/dev/null || fail "validity-vendor not on PATH"
expect "^validity-vendor " validity-vendor --version
expect "^validity-daemon " "$daemon" --version
expect "not installed" validity-vendor check
if [ "$init" = systemd ]; then
    test -f /usr/lib/systemd/system/validity-daemon.service || fail "unit missing"
    test -f /usr/lib/udev/rules.d/60-validity-daemon.rules || fail "udev rule missing"
    systemd-analyze verify --man=no validity-daemon.service || fail "unit does not verify"
else
    test -x /etc/init.d/validity-daemon || fail "OpenRC script missing"
fi

if [ "$distro" = debian ]; then
    say "PAM: the validity-fprint profile is shipped, not enabled"
    expect '^Default: no$' cat /usr/share/pam-configs/validity-fprint
    cmp /etc/pam.d/common-auth /tmp/common-auth.before || fail "installing the package changed common-auth"
    # Enabled by the administrator; the package's prerm must take it out on
    # removal ("nothing left behind" compares every file, /etc/pam.d included).
    pam-auth-update --enable validity-fprint
    expect 'pam_fprintd\.so max-tries=1 timeout=10' cat /etc/pam.d/common-auth
    expect 'pam_echo\.so %u reconnu, appuyez sur Entr' cat /etc/pam.d/common-auth
fi

say "how net.reactivated.Fprint is activated now"
case "$distro" in
    debian)
        expect 'Exec=/usr/libexec/validity-daemon' cat "$FPRINT_SERVICE"
        expect "diversion of $FPRINT_SERVICE to $FPRINT_SERVICE.fprintd by validity-daemon" dpkg-divert --list
        expect "$FPRINTD_EXEC" cat "$FPRINT_SERVICE.fprintd"
        ;;
    fedora | archlinux)
        # fprintd's file is untouched; its unit hands over to ours.
        expect "$FPRINTD_EXEC" cat "$FPRINT_SERVICE"
        expect 'validity-daemon.service' systemctl show -p Requires --value fprintd.service
        systemd-analyze verify --man=no fprintd.service || fail "fprintd.service with the drop-in does not verify"
        ;;
    alpine)
        # No systemd: fprintd's file is untouched and validity-daemon runs as an
        # OpenRC service that owns the name first.
        expect "$FPRINTD_EXEC" cat "$FPRINT_SERVICE"
        ;;
esac

say "smoke test: the daemon on the emulated sensor, fprintd's client in front"
if [ "$init" = systemd ]; then
    systemctl stop validity-daemon.service fprintd.service 2>/dev/null || true
fi
# With the shipped example configuration, which must parse; the Fedora and
# Arch images install no documentation (nodocs, NoExtract), so not there.
example=/usr/share/doc/validity-daemon/validity.toml.example
config=()
if [ -f "$example" ]; then config=(--config "$example"); else echo "    (no $example: this image installs no documentation)"; fi
"$daemon" --fake-sensor --state-dir /tmp/validity-fake "${config[@]}" >/tmp/fake.log 2>&1 &
fake=$!
for _ in $(seq 1 150); do has_owner net.reactivated.Fprint && break; sleep 0.2; done
has_owner net.reactivated.Fprint || { sed 's/^/    daemon: /' /tmp/fake.log; fail "the daemon on the emulated sensor did not take the bus name"; }
expect "^$daemon --fake-sensor" owner_cmdline net.reactivated.Fprint
expect 'no fingers enrolled' fprintd-list root
kill "$fake"
wait "$fake" || true
wait_for no_owner net.reactivated.Fprint
sed 's/^/    daemon: /' /tmp/fake.log | tail -5

if [ "$init" = systemd ]; then
    say "D-Bus activation starts validity-daemon (no sensor here: no device)"
    eventually 'No devices available' fprintd-list root
    wait_for has_owner net.reactivated.Fprint
    expect "^$daemon" owner_cmdline net.reactivated.Fprint
    expect '^active$' systemctl is-active validity-daemon.service
    journalctl -u validity-daemon.service --no-pager | tail -5 | sed 's/^/    /'
    # Left running: removing the package must stop it.
else
    say "OpenRC service owns the name (no sensor here: no device)"
    rc-service validity-daemon start
    wait_for has_owner net.reactivated.Fprint
    expect "^$daemon" owner_cmdline net.reactivated.Fprint
    eventually 'No devices available' fprintd-list root
    # Left running: removing the package must stop it.
fi

if [ "${VENDOR_ONLINE:-}" = 1 ]; then
    say "vendor files from Lenovo"
    expect 'vendor files installed' validity-vendor install
    expect 'already in place' validity-vendor install
    expect 'in place' validity-vendor check
fi

say "remove (the daemon is running)"
has_owner net.reactivated.Fprint || fail "the daemon should be running here"
remove_pkg
installed && fail "still installed"
wait_for no_owner net.reactivated.Fprint
if running "$daemon"; then fail "validity-daemon still running after removal"; fi

say "fprintd has its activation back"
expect "$FPRINTD_EXEC" cat "$FPRINT_SERVICE"
if [ "$distro" = debian ]; then
    dpkg-divert --list | grep -q validity && fail "diversion left behind"
    cmp /etc/pam.d/common-auth /tmp/common-auth.before || fail "common-auth differs after removal"
    echo "    common-auth byte-identical to the one before installation"
    ls "$FPRINT_SERVICE".* 2>/dev/null && fail "diverted copy left behind"
fi

say "nothing left behind"
after=$(mktemp)
snapshot >"$after"
if ! diff -u "$before" "$after"; then
    fail "the system differs after removal (above)"
fi
echo "    identical: $(wc -l <"$before") entries"

say "fprintd answers again"
eventually 'No devices available' fprintd-list root
wait_for has_owner net.reactivated.Fprint
expect 'fprintd' owner_cmdline net.reactivated.Fprint

say "cycle $distro: OK"
