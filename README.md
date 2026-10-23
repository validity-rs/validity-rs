# validity-rs

A Rust driver and fprintd-compatible D-Bus service for the **Synaptics/Validity
"match-on-chip" fingerprint sensors** found in many 2016–2018 ThinkPads, which
`libfprint` lists as *unsupported*.

> **Status: pre-alpha, not usable yet.** Phase 0 (validating the hardware against the
> reference implementation) has not started. Do not install this on a machine you
> depend on.

## Why

Sensors such as `06cb:009a` (ThinkPad T480, T480s, X280, X1 Carbon 6th gen) do the
matching inside the chip and talk to the host over a proprietary, TLS-like
encrypted channel. `libfprint` does not support them. The only working driver
today is [python-validity](https://github.com/uunicorn/python-validity) (MIT), together with
[open-fprintd](https://github.com/uunicorn/open-fprintd) (GPL-2.0). It is hard to install and
barely maintained.

`validity-rs` aims to be a **drop-in replacement for `fprintd`** on these devices:
same D-Bus API (`net.reactivated.Fprint`), so that `libpam-fprintd`, GNOME, KDE,
LightDM and screen lockers keep working unchanged.

## Supported devices

| USB ID | Sensor | Status |
|---|---|---|
| `06cb:009a` | Synaptics "Metallica MIS" | **First target** |
| `138a:0090`, `138a:0097`, `06cb:009d` | Validity / Synaptics | Later (supported by python-validity) |

## Design principles

1. **Never lock anyone out.** The service must fail safe. If the sensor, the
   firmware or the daemon misbehaves, authentication falls back to the password.
   Configure PAM so that the fingerprint is `sufficient`, never `required`.
2. **No biometric data leaves the chip.** Templates are stored and matched on the
   sensor; the host only manages the encrypted session and the flash records.
3. **Byte-exact against the reference.** The protocol is ported from
   python-validity and checked with replay tests against captured sessions.
4. **No proprietary blobs in this repository.** The Synaptics firmware extension is
   downloaded from the vendor at install time and verified by SHA-256.
5. **No device secrets in this repository.** See *Privacy* below.

## Architecture (planned)

```
crates/
  validity-proto   USB transport (rusb), TLS-like channel (RustCrypto: ECDH P-256,
                   AES, HMAC), commands, flash and record database
  validity-fwext   firmware extension download, verification and upload
  validity-daemon  fprintd-compatible D-Bus service (zbus), systemd unit
tests/replay/      replay tests over synthetic or anonymised traces
```

## Roadmap

- [ ] **Phase 0** – run python-validity on real hardware; pairing, enroll, identify;
      capture reference traces (kept private, see *Privacy*).
- [ ] **Phase 1** – `validity-proto`: USB, encrypted channel, commands; replay tests.
- [ ] **Phase 2** – `validity-daemon`: `net.reactivated.Fprint` over D-Bus, hardened systemd unit.
- [ ] **Phase 3** – PAM / desktop integration notes, enrolment UX, packaging (`.deb`).
- [ ] **Phase 4** – other sensors from python-validity, distribution packages.

## Getting started (contributors)

Requirements: Rust (stable, edition 2024), `libusb-1.0` headers (`libusb-1.0-0-dev`
on Debian), `dbus-daemon` (the daemon's integration tests start a private bus),
and for hardware work a machine with one of the sensors above.

```bash
git clone <this repo> && cd validity-rs
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

Hardware access requires permission on the USB device (a udev rule will be
provided). Never run experimental builds on your only machine without a
password login path.

To study the protocol, read python-validity's `validitysensor/` (`usb.py`, `tls.py`,
`sensor.py`, `db.py`, `flash.py`) next to the corresponding modules here.

## Privacy

Captured USB sessions contain the **sensor serial number, pairing keys and TLS
session keys** of the capturing device. **Never commit raw captures.** Replay tests
use synthetic traces, or traces anonymised by `tests/replay/anonymise` (to be
written), which must be reviewed before committing. Do not commit flash dumps.
`gitleaks` runs in CI.

## Contributing

Issues and pull requests are welcome. Please include the device USB ID
(`lsusb`), the kernel and distribution versions, and logs with secrets removed.
Code must pass `cargo fmt`, `clippy -D warnings` and the test suite.

## License

MIT, see [LICENSE](LICENSE). Portions are ported from
[python-validity](https://github.com/uunicorn/python-validity) (MIT, © its authors); see
[NOTICE](NOTICE).
