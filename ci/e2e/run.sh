#!/usr/bin/env bash
# End-to-end test, run as root in the e2e container (docker/Dockerfile.e2e):
# a system bus with polkit, validity-daemon's service with the emulated sensor
# (examples/fake_daemon.rs), and the stock clients in front of it:
# fprintd-list / -enroll / -verify / -delete and pam_fprintd through pamtester.
#
#   ci/run.sh e2e        (builds the image and runs this inside it)
set -euo pipefail
cd "$(dirname "$0")/../.."

say() { printf '\n\033[1m-- %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
# expect <pattern>[@@<pattern>...] <command...>: runs the command, shows its
# output, fails unless every pattern matches a line of it.
expect() {
    local pats=$1 out pat; shift
    out=$("$@" 2>&1) || true
    printf '%s\n' "$out" | sed 's/^/    /'
    while IFS= read -r pat; do
        printf '%s\n' "$out" | grep -qE "$pat" || fail "expected /$pat/ from: $*"
    done < <(printf '%s\n' "${pats//@@/$'\n'}")
}
ctl() {
    dbus-send --system --print-reply --dest=org.validityrs.FakeSensor \
        /org/validityrs/FakeSensor "org.validityrs.FakeSensor.$1" "${@:2}" >/dev/null
}
touch_finger() { local f; for f in "$@"; do ctl Touch "uint32:$f"; done; }
ctl_pending() {
    dbus-send --system --print-reply --dest=org.validityrs.FakeSensor /org/validityrs/FakeSensor \
        org.validityrs.FakeSensor.PendingTouches | awk '/uint32/ { print $2 }'
}
# The device paths GetDevices returns, one per line.
devices() {
    dbus-send --system --print-reply --dest=net.reactivated.Fprint /net/reactivated/Fprint/Manager \
        net.reactivated.Fprint.Manager.GetDevices | awk '/object path/ { print $3 }'
}
no_devices() { [ -z "$(devices)" ]; }
has_owner() {
    dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.NameHasOwner "string:$1" | grep -q 'boolean true'
}
wait_for() {
    local i
    for i in $(seq 1 100); do "$@" && return 0; sleep 0.1; done
    fail "timed out: $*"
}
# elapsed_below <seconds> <command...>: the command must finish in time. Call
# it outside command substitutions (expect's), so that its failure ends the run.
elapsed_below() {
    local limit=$1 start end; shift
    start=$(date +%s.%N)
    "$@" || true
    end=$(date +%s.%N)
    awk -v s="$start" -v e="$end" -v l="$limit" 'BEGIN { d = e - s; printf "    took %.2fs\n", d; exit !(d < l) }' \
        || fail "took too long (limit ${limit}s): $*"
}

say "build"
cargo build -q -p validity-daemon --example fake_daemon --bin validity-daemon
FAKE=$PWD/target/debug/examples/fake_daemon

say "system bus and polkit"
# The daemon's own bus policy (as packaged), and access to the emulator's
# control object for this test.
install -m 0644 packaging/common/dbus-1/system.d/validity-daemon.conf /etc/dbus-1/system.d/
install -m 0644 ci/e2e/fake-sensor.conf /etc/dbus-1/system.d/
# As packaged: our activation file replaces fprintd's, and the daemon is
# installed where it points.
install -m 0644 packaging/common/dbus-1/system-services/net.reactivated.Fprint.service \
    /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
install -m 0755 target/debug/validity-daemon /usr/libexec/validity-daemon
mkdir -p /run/dbus
rm -f /run/dbus/pid
dbus-daemon --system --fork
wait_for test -S /run/dbus/system_bus_socket
/usr/lib/polkit-1/polkitd --no-debug >/tmp/polkitd.log 2>&1 &
wait_for has_owner org.freedesktop.PolicyKit1

say "daemon with the emulated sensor"
"$FAKE" >/tmp/daemon.log 2>&1 &
DAEMON=$!
trap 'echo "--- daemon log"; tail -40 /tmp/daemon.log' EXIT
wait_for has_owner net.reactivated.Fprint
wait_for has_owner org.validityrs.FakeSensor

say "interfaces against fprintd's installed XML"
expect "checked against /usr/share/dbus-1/interfaces/net.reactivated.Fprint.Device.xml@@checked against /usr/share/dbus-1/interfaces/net.reactivated.Fprint.Manager.xml@@test result: ok. 1 passed" \
    cargo test -q -p validity-daemon --test dbus interfaces_match_fprintd -- --nocapture

say "fprintd-list: nothing enrolled"
expect "no fingers enrolled" fprintd-list root

say "fprintd-enroll: duplicate check + 5 images"
touch_finger 1 1 1 1 1 1
expect "Enroll result: enroll-completed" fprintd-enroll -f right-index-finger root
expect "right-index-finger" fprintd-list root

say "fprintd-verify: match"
touch_finger 1
expect "Verify result: verify-match \(done\)" fprintd-verify root
fprintd_verify_status() { touch_finger "$1"; fprintd-verify root >/dev/null 2>&1; }
fprintd_verify_status 1 || fail "fprintd-verify exit status on a match"

say "fprintd-verify: unknown finger"
touch_finger 9
expect "Verify result: verify-no-match \(done\)" fprintd-verify root
! fprintd_verify_status 9 || fail "fprintd-verify exit status on a mismatch"

say "fprintd-verify: failed capture, then match"
ctl ScanError
touch_finger 1
expect "verify-retry-scan \(not done\)@@verify-match \(done\)" fprintd-verify root

say "polkit: an unprivileged user outside a session gets nothing"
id e2euser >/dev/null 2>&1 || useradd --create-home e2euser
expect "PermissionDenied|Not Authorized" runuser -u e2euser -- fprintd-list root
expect "PermissionDenied|Not Authorized" runuser -u e2euser -- fprintd-enroll -f left-thumb
expect "PermissionDenied|Not Authorized" runuser -u e2euser -- fprintd-verify
expect "PermissionDenied|Not Authorized" runuser -u e2euser -- fprintd-delete root
[ "$(ctl_pending)" = 0 ] || fail "a denied client reached the sensor"

say "pam_fprintd through pamtester"
cat >/etc/pam.d/validity-e2e <<'PAM'
auth sufficient pam_fprintd.so max-tries=1 timeout=10
auth required pam_deny.so
account required pam_permit.so
PAM
touch_finger 1
expect "successfully authenticated" pamtester validity-e2e root authenticate
touch_finger 9
expect "Authentication failure" pamtester validity-e2e root authenticate
# pam_fprintd disconnects without Release after a match: the device must be free.
touch_finger 1
expect "successfully authenticated" pamtester validity-e2e root authenticate

say "password fallback: sensor unplugged"
ctl Unplug
# Lost sensors usually come back (re-enumeration): listed for a few seconds...
devices | grep -q /net/reactivated/Fprint/Device/0 || fail "reported gone at once"
# ...then gone, and PAM falls through at once.
wait_for no_devices
elapsed_below 3 expect "Authentication failure" pamtester validity-e2e root authenticate
expect "No devices available" fprintd-list root
ctl Plug
wait_for fprintd-list root >/dev/null 2>&1
touch_finger 1
expect "successfully authenticated" pamtester validity-e2e root authenticate

say "fprintd-delete"
expect "Fingerprints of user root deleted" fprintd-delete root
expect "no fingers enrolled" fprintd-list root

say "password fallback: daemon killed"
kill -9 "$DAEMON"
wait "$DAEMON" 2>/dev/null || true
trap - EXIT
# The next client activates the installed daemon through D-Bus: no sensor
# there, so pam_fprintd gives up at once.
elapsed_below 5 expect "Authentication failure" pamtester validity-e2e root authenticate
expect "No devices available" fprintd-list root

say "e2e: OK"
