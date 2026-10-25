# validity-rs

[![CI](https://github.com/validity-rs/validity-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/validity-rs/validity-rs/actions/workflows/ci.yml)
[![Packages](https://github.com/validity-rs/validity-rs/actions/workflows/packages.yml/badge.svg)](https://github.com/validity-rs/validity-rs/actions/workflows/packages.yml)
[![Release](https://img.shields.io/github/v/release/validity-rs/validity-rs)](https://github.com/validity-rs/validity-rs/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

validity-rs is a Linux driver, written in Rust, for the Synaptics/Validity
"match-on-chip" fingerprint sensors found in ThinkPads of the 2018 generation,
which libfprint does not support. It ships as `validity-daemon`, a drop-in
replacement for fprintd's service, so fprintd's tools, `pam_fprintd`, desktops
and screen lockers work with these sensors unchanged.

## Contents

- [Status](#status)
- [Supported hardware](#supported-hardware)
- [Supported distributions](#supported-distributions)
- [Install](#install)
- [First start: pairing the sensor](#first-start-pairing-the-sensor)
- [Enrol a finger](#enrol-a-finger)
- [Log in with a finger](#log-in-with-a-finger)
- [Security and privacy](#security-and-privacy)
- [Known limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [For developers](#for-developers)
- [License](#license)

## Status

Pre-1.0. The whole protocol (pairing, firmware upload, calibration, enrolment,
identification) runs in Rust on a ThinkPad T480 with Debian 13, and the daemon,
the PAM profile and the [Fingerprints app](https://github.com/validity-rs/fingerprint-settings)
have been run there with LightDM. Hardware validation is still going on
([#2](https://github.com/validity-rs/validity-rs/issues/2),
[#11](https://github.com/validity-rs/validity-rs/issues/11)).

| | Released in 0.1.0 | On `master`, ships with the next release |
|---|---|---|
| Debian 13 package and APT suite `trixie` | yes | |
| Fedora, Arch Linux, Alpine packages (GitHub release) | yes | |
| Ubuntu 24.04 and 26.04 packages and APT suites | | yes |
| `validity-fprint` PAM profile and `pam_validity.so` | | yes |

## Supported hardware

| USB ID | Sensor | Status |
|---|---|---|
| `06cb:009a` | Synaptics "Metallica MIS" | Supported. Tested on a ThinkPad T480 only. |
| `138a:0090`, `138a:0097`, `06cb:009d` | other Validity / Synaptics sensors | Not supported yet (python-validity drives them). |

The same `06cb:009a` sensor is fitted to other models, such as the ThinkPad
T480s, X280 and X1 Carbon 6th gen. They should work, but nobody has tested
them yet: reports are welcome. Check your sensor with:

```bash
lsusb | grep -iE '06cb|138a'
```

## Supported distributions

| Distribution | Daemon | Fingerprints app | How |
|---|---|---|---|
| Debian 13 (trixie) | yes | yes | APT repository |
| Ubuntu 26.04 LTS (resolute) | next release | next release | APT repository |
| Ubuntu 24.04 LTS (noble) | next release | no (its GTK 4.14 and libadwaita 1.5 are too old) | APT repository |
| Fedora 44 | yes | yes | package from the GitHub release |
| Arch Linux | yes | yes | package from the GitHub release |
| Alpine 3.24 | yes | yes | package from the GitHub release |

Packages are amd64 (x86_64) only. Every package is built, installed, smoke-tested
and removed in CI on its distribution. The Fedora and Arch Linux packages are
not in COPR or the AUR yet: the COPR project is pending, and AUR account
registration is closed at the moment.

## Install

The package depends on fprintd and takes over only its D-Bus activation, so
every fprintd client reaches validity-daemon. It never changes your PAM
configuration.

During installation, `validity-vendor install` downloads Lenovo's Synaptics
driver package and extracts the two files the sensor needs, checking all three
against pinned SHA-256 hashes. Nothing proprietary is stored in this repository
or in any package. Offline, the installation still succeeds; run
`sudo validity-vendor install` later, or
`sudo validity-vendor install --archive nz3gf07w.exe` with a copy fetched
elsewhere.

### Debian 13 (trixie)

```bash
sudo apt install curl gpg
curl -fsSLO https://validity-rs.github.io/apt/validity-rs-archive-keyring.gpg
gpg --show-keys --with-fingerprint validity-rs-archive-keyring.gpg
#   must show 59CB F35F 3147 A424 BE25  DF07 8F4B 8482 B486 C8FD
sudo install -m 0644 validity-rs-archive-keyring.gpg /usr/share/keyrings/
sudo curl -fsSL -o /etc/apt/sources.list.d/validity-rs.sources \
    https://validity-rs.github.io/apt/validity-rs.sources
sudo apt update
sudo apt install validity-rs-archive-keyring validity-daemon fingerprint-settings unattended-upgrades
```

The keyring package then owns the key and the source, and keeps them up to
date. The key is trusted for this repository only (`Signed-By`).
unattended-upgrades is optional: with it, new versions install themselves.

### Ubuntu 26.04 (resolute) and 24.04 (noble)

The Ubuntu suites are published with the next release. Until then the URLs
below return 404. Same steps as on Debian, with the source of your release:

```bash
sudo apt install curl gpg
curl -fsSLO https://validity-rs.github.io/apt/validity-rs-archive-keyring.gpg
gpg --show-keys --with-fingerprint validity-rs-archive-keyring.gpg
#   must show 59CB F35F 3147 A424 BE25  DF07 8F4B 8482 B486 C8FD
sudo install -m 0644 validity-rs-archive-keyring.gpg /usr/share/keyrings/
. /etc/os-release
sudo curl -fsSL -o /etc/apt/sources.list.d/validity-rs.sources \
    "https://validity-rs.github.io/apt/validity-rs-$VERSION_CODENAME.sources"
sudo apt update
sudo apt install validity-rs-archive-keyring validity-daemon unattended-upgrades
sudo apt install fingerprint-settings   # 26.04 only
```

### Fedora, Arch Linux, Alpine

Download the files from the
[latest release](https://github.com/validity-rs/validity-rs/releases/latest)
(and the app's from
[fingerprint-settings](https://github.com/validity-rs/fingerprint-settings/releases/latest)),
check them (see [Verify a download](#verify-a-download)), then:

```bash
# Fedora 44
sudo dnf install ./validity-daemon-0.1.0-1.fc44.x86_64.rpm
# Arch Linux
sudo pacman -U validity-daemon-0.1.0-1-x86_64.pkg.tar.zst
# Alpine 3.24 (the CI's signing key is not published, hence --allow-untrusted)
sudo apk add --allow-untrusted validity-daemon-0.1.0-r0.apk validity-daemon-openrc-0.1.0-r0.apk
sudo rc-update add validity-daemon default && sudo rc-service validity-daemon start
```

On Alpine there is no systemd to start the daemon on demand: enable the OpenRC
service, or fprintd answers instead (and finds no sensor; the password still
works).

### Verify a download

Every file of a release has a GitHub build provenance attestation, and
`SHA256SUMS` is signed with the APT repository key:

```bash
gh attestation verify <file> --repo validity-rs/validity-rs
gpgv --keyring ./validity-rs-archive-keyring.gpg SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

### Uninstall

Remove the package (`sudo apt purge validity-daemon`, `sudo dnf remove
validity-daemon`, `sudo pacman -R validity-daemon`, `sudo apk del
validity-daemon`). fprintd gets its D-Bus activation back and
`/var/lib/validity` (calibration, vendor files) is deleted. The fingerprints
stay on the sensor.

## First start: pairing the sensor

The sensor must be paired with the computer once. Pairing erases the
sensor's flash, including any fingerprints and any pairing with Windows, so
the daemon never does it on its own. If the sensor already works with this
installation (as after an earlier pairing on the same machine), skip this.

Ask the daemon:

```bash
fprintd-list "$USER"
journalctl -u validity-daemon -b
```

If the log says *the sensor flash is blank: the sensor is not paired with
this computer* or *the sensor is paired with another computer*, pair it. This
step is not packaged yet: it uses a hardware example from a source build
([Rust](https://rustup.rs) 1.99 or later):

```bash
git clone https://github.com/validity-rs/validity-rs && cd validity-rs
cargo build --release --example session
sudo systemctl stop validity-daemon   # Alpine: sudo rc-service validity-daemon stop
V=/var/lib/validity/vendor
# Only if paired with another computer or with Windows: erase the sensor.
sudo target/release/examples/session $V/synaWudfBioUsb.dll /var/lib/validity/calibration.bin reset
# Pair, upload the firmware extension, calibrate, list the (empty) database.
sudo VALIDITY_FWEXT=$V/6_07f_lenovo_mis_qm.xpfwext \
    target/release/examples/session $V/synaWudfBioUsb.dll /var/lib/validity/calibration.bin list
```

The pairing is bound to this computer's DMI product name and serial number.
After a mainboard replacement, pair again.

## Enrol a finger

With the **Fingerprints** app (« Empreintes digitales » in French), from the
desktop's Settings menu: one screen, one button, to register your right index
finger or remove it. It is meant for desktops without fingerprint settings of
their own (Xfce, MATE, LXQt). GNOME and KDE Plasma have their own
fingerprint settings, which use the same fprintd API (not tested yet).

Or on the command line:

```bash
fprintd-enroll                   # right index finger by default; -f <finger> for another
fprintd-verify -f any            # check it (without -f, fprintd-verify names your first finger)
fprintd-list "$USER"
fprintd-delete "$USER"           # remove all your fingerprints
```

Who may add or remove a fingerprint is fprintd's polkit policy, which
usually asks for your own password: a polkit agent must run in the session.

## Log in with a finger

The password always works: no package makes the fingerprint `required`, and
every failure of the sensor, the daemon or the PAM module falls back to the
password.

### Debian and Ubuntu: the `validity-fprint` profile (next release)

The .deb ships an optional pam-auth-update profile, off by default, and its
module `pam_validity.so`. It replaces libpam-fprintd's `fprintd` profile
(which it disables) and does not need libpam-fprintd.

```bash
sudo pam-auth-update --disable fprintd --enable validity-fprint   # turn it on
sudo pam-auth-update --disable validity-fprint --enable fprintd   # back to fprintd's
sudo pam-auth-update --disable validity-fprint                    # password only
```

On **LightDM** (the greeter and light-locker), the password comes first:

1. Type your password and press Enter: you are in, the sensor is not used.
2. Or leave the password empty and press Enter, then touch the sensor
   (within 30 s; it lights up while it waits). On a match the greeter shows
   `Access granted`; press Enter once more to log in.

Everywhere else (sudo, su, the console, polkit dialogs) the order is
fprintd's: touch the sensor within 10 s, or wait for the password prompt.
Nothing is printed while it waits.

### Other setups

With libpam-fprintd (Debian, Ubuntu), `fprintd-pam` (Fedora) or your
distribution's equivalent, `pam_fprintd` works against validity-daemon as it
does against fprintd. Keep the fingerprint line `sufficient` (or
`[success=end default=ignore]`), never `required`.

## Security and privacy

- **Match on chip.** Fingerprint templates are stored and matched inside the
  sensor. They never reach the computer; the host only learns which enrolled
  record matched.
- **Encrypted channel.** The host and the sensor talk over the sensor's
  TLS-like protocol (ECDH P-256, AES-256-CBC, HMAC-SHA256). The sensor's key
  must be signed by the firmware key; the host's key is stored on the sensor,
  sealed with a key derived from the computer's DMI identity.
- **Pairing rewrites the sensor flash.** An existing pairing (with Windows,
  for instance) and its fingerprints are lost. Nothing destructive happens
  without an explicit command.
- **The claimed user only.** A verification succeeds only on one of the
  claimed user's own fingers, never on another user's or on a Windows record.
- **Fail safe.** PAM is never touched by a package, the fingerprint is never
  `required`, and every error falls back to the password. `pam_validity.so`
  talks to the system bus at its fixed address and accepts results only from
  the owner of `net.reactivated.Fprint`.
- **Hardened service.** The systemd unit has no network access
  (`IPAddressDeny=any`), a read-only system, and a system call filter.
- **Vendor files** are downloaded from Lenovo and checked by SHA-256; the
  daemon checks the driver file again at every start and never downloads
  anything itself.

## Known limitations

- **One sensor model**, `06cb:009a`, tested on one laptop model.
- **LightDM needs an extra Enter** after `Access granted`: LightDM's greeters
  wait for it after an authentication that asked no question.
- **A wrong password also leads to the finger** on LightDM: PAM cannot tell an
  empty password from a wrong one. A matching finger then logs in, which it
  may do anyway; anything else fails.
- **Pairing is a manual step** from a source build (see above).
- **No COPR or AUR packages yet**, and no Ubuntu packages before the next
  release. Ubuntu 22.04 is not supported.
- The Alpine package needs `rc-update add validity-daemon default`.

## Troubleshooting

- `journalctl -u validity-daemon` shows the daemon's view (setup errors,
  timeouts, recoveries).
- `sudo validity-vendor check` tells whether the vendor files are in place
  (exit status 4 if missing or damaged).
- No wait on the sensor is unbounded: a finger wait ends after 30 s
  (`finger_timeout_ms` in `/etc/validity/validity.toml`; every setting is in
  `/usr/share/doc/validity-daemon/validity.toml.example`), any other after a
  few seconds, and a sensor that stops answering is rebooted, then reset on
  its USB port.
- A trace for a bug report: `--trace-sensor-traffic` on the daemon, or
  `VALIDITY_LOG=trace` on the hardware examples. It holds opcodes, lengths and
  status words, never keys, templates or flash contents
  ([details](docs/development.md#traces)).

Please open an [issue](https://github.com/validity-rs/validity-rs/issues) with
the USB ID (`lsusb`), the laptop model, the distribution and kernel versions,
and the log.

## For developers

The full guide is [docs/development.md](docs/development.md); packaging,
the APT repository and releases are in [docs/packaging.md](docs/packaging.md);
the hardware validation against the reference is [docs/phase-0.md](docs/phase-0.md).

| Crate | What |
|---|---|
| `crates/validity-proto` | The sensor protocol: USB transport (nusb), TLS-like channel, pairing, firmware upload, calibration, flash and on-chip database, enrolment, identification, session replay. |
| `crates/validity-vendor` | `validity-vendor`: downloads Lenovo's package, extracts and checks the vendor files, switches them in atomically. |
| `crates/validity-daemon` | `validity-daemon`: the `net.reactivated.Fprint` D-Bus service (zbus), polkit, suspend handling, recovery. |
| `crates/pam-validity` | `pam_validity.so`: the PAM module of the `validity-fprint` profile. |

```bash
cargo build
cargo test                                   # all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
ci/run.sh                                    # the quick CI set, as on GitHub
git config core.hooksPath .githooks          # pre-push: the quick set on each pushed commit
```

The protocol is ported from [python-validity](https://github.com/uunicorn/python-validity)
and checked byte for byte against it (test vectors from the reference on
synthetic inputs). The CI also runs an end-to-end test with fprintd's own
clients, `pam_fprintd` and polkit against the daemon on an emulated sensor,
fuzzing of every parser, and mutation testing with no surviving mutant.
Contributions are welcome; see [Contributing](docs/development.md#contributing).

## License

MIT, see [LICENSE](LICENSE). The protocol is ported from
[python-validity](https://github.com/uunicorn/python-validity) (MIT, © 2020
uunicorn); its notice is in [NOTICE](NOTICE). open-fprintd (GPL-2.0) was read
for its behaviour only; none of its code is used.
