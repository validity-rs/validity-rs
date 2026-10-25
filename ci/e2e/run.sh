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

# The pam-auth-update profile the .deb ships (packaging/debian/pam-configs),
# over the stock common-* files. pam_auth <service> <password>: pamtester's
# authenticate and setcred for root (what LightDM calls), the password fed to
# any prompt; output in $PAM_OUT, exit status in $PAM_RC.
PASSWORD=e2e-Passw0rd
GUIDE="Posez le doigt sur le lecteur."
MESSAGE="root reconnu, appuyez sur Entrée."
pam_auth() {
    PAM_RC=0
    PAM_OUT=$(pamtester "$1" root authenticate setcred 2>&1 <<<"$2") || PAM_RC=$?
    printf '%s\n' "$PAM_OUT" | sed 's/^/    /'
}
saw() { printf '%s\n' "$PAM_OUT" | grep -qF -- "$1" || fail "expected '$1'"; }
not_saw() { if printf '%s\n' "$PAM_OUT" | grep -qF -- "$1"; then fail "unexpected '$1'"; fi; }
granted() { [ "$PAM_RC" = 0 ] || fail "refused (exit $PAM_RC)"; saw "successfully authenticated"; }
# Any failure code: pam_unix gives "Authentication failure", the finger after
# a password on LightDM gives pam_fprintd's own (die), e.g. "Have exhausted
# maximum number of retries" for a refused finger.
refused() { [ "$PAM_RC" != 0 ] || fail "granted"; not_saw "successfully authenticated"; not_saw "reconnu"; }
prompts() { [ "$(printf '%s\n' "$PAM_OUT" | grep -o 'Password:' | wc -l)" = "$1" ] || fail "expected $1 password prompt(s)"; }
# LightDM, the password first: the right one at once, the sensor untouched.
lightdm_password() {
    elapsed_below 3 pam_auth lightdm "$PASSWORD"
    granted; prompts 1; not_saw "$GUIDE"; not_saw "reconnu"; not_saw "finger"
}
# LightDM, empty (or wrong) password, then a refused or missing finger: failure.
lightdm_refused() {
    local pass=$1 touch=${2:-}
    [ -z "$touch" ] || touch_finger "$touch"
    pam_auth lightdm "$pass"
    refused; prompts 1; saw "$GUIDE"
}
# Other services, as with fprintd's profile: the finger first, then the
# password, the right one only, and none of our messages.
other_password_only() {
    local touch=${1:-}
    [ -z "$touch" ] || touch_finger "$touch"
    pam_auth validity-other "$PASSWORD"
    granted; prompts 1; not_saw "Posez"; not_saw "reconnu"
    [ -z "$touch" ] || touch_finger "$touch"
    pam_auth validity-other wrong-password
    refused; prompts 1; not_saw "Posez"; saw "Authentication failure"
}
# The five common-* files, saved under a name and compared byte for byte.
snap_pam() { rm -rf "/tmp/pam-$1"; mkdir "/tmp/pam-$1"; cp -a /etc/pam.d/common-* "/tmp/pam-$1/"; }
same_pam() {
    local f
    for f in /tmp/pam-"$1"/common-*; do
        cmp "$f" "/etc/pam.d/$(basename "$f")" || fail "/etc/pam.d/$(basename "$f") differs from the '$1' state"
    done
    diff <(cd /etc/pam.d && printf '%s\n' common-*) <(cd "/tmp/pam-$1" && printf '%s\n' common-*) \
        || fail "common-* files added or removed"
    echo "    common-* byte-identical to the '$1' state"
}
no_fprint_owner() { ! has_owner net.reactivated.Fprint; }
owner_pid() {
    dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.GetConnectionUnixProcessID "string:$1" | awk '/uint32/ { print $2 }'
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

say "pam-auth-update: validity-fprint over the T480's setup (fprintd's profile on)"
export DEBIAN_FRONTEND=noninteractive
if grep -q pam_fprintd /etc/pam.d/common-auth; then fail "the image's common-auth already has pam_fprintd"; fi
snap_pam stock
pam-auth-update --enable fprintd
expect '^auth[[:space:]]+\[success=2 default=ignore\][[:space:]]+pam_fprintd\.so max-tries=1 timeout=10' cat /etc/pam.d/common-auth
snap_pam fprintd
install -m 0644 packaging/debian/pam-configs/validity-fprint /usr/share/pam-configs/
pam-auth-update --package
same_pam fprintd
pam-auth-update --disable fprintd --enable validity-fprint
# The whole stack, exactly. LightDM: pam_unix first (success: pam_permit),
# then the finger, whose failure ends the stack (die). Other services jump
# straight to fprintd's own line, then pam_unix, as with fprintd's profile.
diff -u <(printf 'auth\t%s\n' \
    $'[success=ignore default=4]\tpam_succeed_if.so quiet service = lightdm' \
    $'[success=6 default=ignore]\tpam_unix.so nullok' \
    $'[default=ignore]\tpam_echo.so Posez le doigt sur le lecteur.' \
    $'[success=ok default=die]\tpam_fprintd.so max-tries=1 timeout=30' \
    $'[default=3]\tpam_echo.so %u reconnu, appuyez sur Entrée.' \
    $'[success=2 default=ignore]\tpam_fprintd.so max-tries=1 timeout=10' \
    $'[success=1 default=ignore]\tpam_unix.so nullok try_first_pass' \
    $'requisite\t\t\tpam_deny.so' \
    $'required\t\t\tpam_permit.so') <(grep '^auth' /etc/pam.d/common-auth) \
    || fail "unexpected common-auth stack"
grep '^auth' /etc/pam.d/common-auth | sed 's/^/    /'
snap_pam ours
echo "root:$PASSWORD" | chpasswd
for svc in lightdm validity-other; do
    printf '@include common-auth\naccount required pam_permit.so\n' >"/etc/pam.d/$svc"
done

say "lightdm: the right password at once, the sensor never asked"
lightdm_password
[ "$(ctl_pending)" = 0 ] || fail "touches left over"

say "lightdm: empty password, matching finger: one line, the message, success"
touch_finger 1
pam_auth lightdm ""
granted; prompts 1; saw "$GUIDE"; saw "$MESSAGE"
[ "$(ctl_pending)" = 0 ] || fail "touch not consumed"

say "lightdm: empty password, unknown finger: failure"
lightdm_refused "" 9
say "lightdm: empty password, no finger (30 s): failure"
# pam_fprintd's 30 s and the sensor's finger deadline (30 s) race: either way, a failure.
lightdm_refused ""
say "lightdm: wrong password, unknown finger: failure"
lightdm_refused wrong-password 9
say "lightdm: wrong password, then a matching finger: success (PAM cannot tell empty from wrong)"
touch_finger 1
pam_auth lightdm wrong-password
granted; prompts 1; saw "$GUIDE"; saw "$MESSAGE"
[ "$(ctl_pending)" = 0 ] || fail "touches left over"

say "another service (sudo, su...), matching finger: no message, no password"
touch_finger 1
pam_auth validity-other wrong-password
granted; prompts 0; not_saw "Posez"; not_saw "reconnu"
say "another service, unknown finger: the password, right one only"
other_password_only 9
say "another service, no finger (pam_fprintd's 10 s timeout): the password, right one only"
other_password_only
[ "$(ctl_pending)" = 0 ] || fail "touches left over"

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

say "daemon without a sensor (D-Bus activated): passwords work, no finger login"
lightdm_password
lightdm_refused ""
lightdm_refused wrong-password
other_password_only

say "no daemon at all (not activatable): passwords work, no finger login"
mv /usr/share/dbus-1/system-services/net.reactivated.Fprint.service /tmp/fprint.service.away
dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.ReloadConfig >/dev/null
if has_owner net.reactivated.Fprint; then kill "$(owner_pid net.reactivated.Fprint)"; fi
wait_for no_fprint_owner
lightdm_password
lightdm_refused ""
lightdm_refused wrong-password
elapsed_below 5 pam_auth validity-other "$PASSWORD"
granted; prompts 1
other_password_only
if has_owner net.reactivated.Fprint; then fail "something serves net.reactivated.Fprint"; fi
mv /tmp/fprint.service.away /usr/share/dbus-1/system-services/net.reactivated.Fprint.service

say "pam_fprintd.so missing (libpam-fprintd removed): passwords work, no finger login"
module=$(find /usr/lib -name pam_fprintd.so | head -1)
[ -n "$module" ] || fail "pam_fprintd.so not found"
mv "$module" /tmp/pam_fprintd.so.away
lightdm_password
lightdm_refused ""
lightdm_refused wrong-password
other_password_only
mv /tmp/pam_fprintd.so.away "$module"

say "pam-auth-update: back to fprintd's profile, then to the stock files, byte for byte"
pam-auth-update --disable validity-fprint --enable fprintd
same_pam fprintd
# Enabled alone, it replaces fprintd's (Conflicts) and gives the same files.
pam-auth-update --enable validity-fprint
same_pam ours
pam-auth-update --disable validity-fprint
same_pam stock
# What the package's prerm runs on removal.
pam-auth-update --enable validity-fprint
pam-auth-update --package --remove validity-fprint
same_pam stock

say "e2e: OK"
