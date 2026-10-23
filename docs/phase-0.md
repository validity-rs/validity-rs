# Phase 0 – validate the hardware against the reference implementation

Goal: before porting anything, prove that the sensor, its firmware extension and the
protocol work on the target machine with the reference implementation
([python-validity](https://github.com/uunicorn/python-validity)), and capture reference
sessions for the replay tests of phase 1.

**Go / no-go:** if pairing, enrolment or identification fails with the reference,
stop. A port cannot do better than a working reference.

## Warnings

- **Pairing rewrites the sensor flash.** Any existing pairing (for example with
  Windows) is lost. This is expected on a Linux-only machine.
- Keep a **password login path** at all times. Do not touch PAM during phase 0.
- Captured sessions contain the sensor serial number, pairing keys and TLS session
  keys. **Store them outside this repository** (see README, *Privacy*).

## Steps

1. Identify the sensor: `lsusb | grep -iE '06cb|138a'`. Expected: `06cb:009a` for the
   first target.
2. Stop anything that may claim the device: `systemctl stop fprintd` (if installed).
3. Run python-validity **from a virtual environment**, not system-wide:
   ```bash
   python3 -m venv ~/pv-venv
   ~/pv-venv/bin/pip install git+https://github.com/uunicorn/python-validity
   ```
   python-validity needs its firmware extension. Follow its README
   (`validity-sensors-firmware`), which downloads the vendor package and extracts the
   blob. Record the SHA-256 of every downloaded file.
4. Factory reset and pair, as documented by python-validity
   (`factory-reset.py`, then its initialisation). Record the exact commands and
   outputs.
5. Enrol two fingers, then identify each one 10 times, plus 10 attempts with an
   un-enrolled finger. Record success and false-reject / false-accept counts.
6. Capture USB traffic for one full session (pairing, enrolment, identification)
   with `usbmon` + `tshark` (or python-validity's trace mode), **into a private
   directory**.
7. Write a short report: commands, outputs (secrets redacted), success rates,
   firmware hashes, kernel and distribution versions.

## Output

- Go / no-go decision.
- Private: raw captures and the full report.
- Public (this repo): the redacted report, hashes of public vendor files, and the
  list of protocol messages observed. No serials, no keys.

## Result (06cb:009a, ThinkPad T480, Debian 13)

**Go.** The reference implementation worked on the first attempt:

| Step | Result |
|---|---|
| Factory reset, pairing, firmware extension upload, calibration | OK (firmware extension 1.2, 2020-01-27) |
| Enrolment, two fingers | OK (11 images; 5 images plus 1 failed capture) |
| Identification, each enrolled finger, 10 attempts | 10/10 and 10/10 (one attempt matched the user's other finger) |
| Identification, a finger that was not enrolled, 10 attempts | 0/10 accepted |

Public vendor files used (Lenovo `nz3gf07w.exe`):

| File | SHA-256 |
|---|---|
| `nz3gf07w.exe` | `c0f8fa6fe1279d4519cc8a381862455948231c45388234b5cf22aa26da6270ef` |
| `6_07f_lenovo_mis_qm.xpfwext` | `ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1` |
| `synaWudfBioUsb.dll` | `aed9f4246bbaca28776c05c169c734cae9763322b03dc00e4319320e1aa2294d` |

python-validity's 06cb:009a command blobs are each the byte `0x06` followed by a
contiguous run of `synaWudfBioUsb.dll`. validity-rs therefore extracts them from the
vendor package by offset and checks them by hash (`crates/validity-proto/src/vendor.rs`).

Observed on hardware:
- Killing the reference in the middle of a capture left the sensor unresponsive (status
  `e653`, then USB timeouts). De-authorising and re-authorising the USB device brought it
  back without losing the enrolled fingers.
- After every session the sensor reboots and is off the bus for about half a second.
  It then returns at a new USB address.

The same session (pairing from an erased sensor, enrolment, identification) was then
repeated entirely with validity-rs.
