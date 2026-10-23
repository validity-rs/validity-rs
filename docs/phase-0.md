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
