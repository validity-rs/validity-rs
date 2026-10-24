# Packaging

Every package is built from one vendored source tarball, in a pinned container
of its distribution, without network. It is then installed, smoke-tested and
removed in a fresh container of the same distribution. `ci/packages/run.sh` does
all of it, locally and in GitHub Actions (`.github/workflows/packages.yml`).

```bash
ci/packages/run.sh                 # every job below
ci/packages/run.sh source          # the vendored source tarball
ci/packages/run.sh debian          # build, lintian, install/smoke/remove cycle
ci/packages/run.sh repro           # build the .deb twice and compare
PKG_CPUS=16-19 ci/packages/run.sh debian   # keep the containers on some CPUs
VENDOR_ONLINE=1 ci/packages/run.sh debian  # the cycle also downloads Lenovo's package
```

Output goes to `target/packages/`.

## What a package installs

| Path | What |
|---|---|
| `/usr/libexec/validity-daemon` | the service |
| `/usr/sbin/validity-vendor` | the vendor file installer (man page `validity-vendor(8)`) |
| `/usr/lib/systemd/system/validity-daemon.service` | hardened unit, `Type=dbus` |
| `/usr/share/dbus-1/system-services/net.reactivated.Fprint.service` | D-Bus activation (Debian: diverted, see below) |
| `/usr/share/dbus-1/system.d/validity-daemon.conf` | bus policy (the same grants as fprintd's) |
| `/usr/lib/udev/rules.d/60-validity-daemon.rules` | starts the unit when a supported sensor appears |
| `/usr/share/metainfo/io.github.validity_rs.validity_daemon.metainfo.xml` | AppStream: the USB IDs it drives |
| `/usr/share/doc/validity-daemon/validity.toml.example` | every setting, with its default |
| `/var/lib/validity/` | state: calibration, `vendor/` (created at run time) |

fprintd's polkit actions and its own bus policy are used as they are: the
package depends on `fprintd`. Its tools (`fprintd-list`, `-enroll`, `-verify`,
`-delete`) and `pam_fprintd` talk to validity-daemon unchanged.

**PAM is never touched.** No package enables fingerprint login. `libpam-fprintd`
is only suggested. Enabling it is the administrator's choice, and it must stay
`sufficient`, never `required`, so that the password always works.

## Vendor files: validity-vendor

The daemon needs two files from Lenovo's Synaptics driver package `nz3gf07w.exe`.
They may not be redistributed, so no package contains them:

| File | SHA-256 |
|---|---|
| `nz3gf07w.exe` | `c0f8fa6fe1279d4519cc8a381862455948231c45388234b5cf22aa26da6270ef` |
| `synaWudfBioUsb.dll` | `aed9f4246bbaca28776c05c169c734cae9763322b03dc00e4319320e1aa2294d` |
| `6_07f_lenovo_mis_qm.xpfwext` | `ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1` |

Every package runs `validity-vendor install` after installation, the same way
everywhere:

1. If `/var/lib/validity/vendor` already holds both files with their hashes,
   nothing happens, and the network is not used.
2. Otherwise the package is downloaded (curl, at most 64 MiB, HTTPS redirects
   only), or read from `--archive FILE`, and its SHA-256 is checked.
3. Both files are extracted (the `inno` crate, a maintained pure-Rust Inno
   Setup reader; see below), and their SHA-256 are checked.
4. They are written and synced into a new `vendor.<stamp>/` directory, and the
   `vendor` link is switched to it by one `rename(2)`. Older sets are removed.
   A lock file serialises concurrent runs.

A failure at any step leaves the previous state as it was. Offline, the
installation of the package still succeeds. The message says that password login
is unaffected and how to finish: `validity-vendor install` once online, or
`validity-vendor install --archive nz3gf07w.exe` with a copy downloaded
elsewhere. `--url` and `VALIDITY_VENDOR_URL` select a mirror; the hashes are
the same. Exit status: 0 done, 1 error, 2 usage, 3 download failed, 4 (`check`)
missing or damaged. Nothing runs at build time.

Why the `inno` crate rather than `innoextract`: it is pure Rust (no runtime
dependency on four distributions), maintained (0.7.1, 2026-10-22, by the author
of winget's `komac`), MIT/Apache-2.0, and it verifies each file's recorded
checksum while extracting. Its tests run against a synthetic Inno Setup 5.5.7
installer written by the test suite (`crates/validity-vendor/tests/support`),
which `innoextract` 1.9 also reads, as an independent check. The real package is
only used on request: `VALIDITY_VENDOR_ARCHIVE=<nz3gf07w.exe>` or
`VALIDITY_VENDOR_ONLINE=1 cargo test -p validity-vendor --test real`. The
download uses `curl` (a package dependency): it honours proxies and the system's
certificate store, and integrity rests on the pinned SHA-256 whatever the
transport.

## Debian (reference target)

Built with cargo-deb 3.8.0 (metadata in `crates/validity-daemon/Cargo.toml`,
maintainer scripts in `packaging/debian/`) in `docker/Dockerfile.pkg-debian`
(`build` stage: the pinned Rust 1.99.1 trixie image of the CI, lintian 2.122.0).
cargo-deb writes no `md5sums`; `ci/packages/build-deb.sh` adds them the way
`dh_md5sums` does, so that `dpkg --verify` and `debsums` work. The package must
be **lintian clean**: any error or warning fails the build, and the remaining
overrides (`packaging/debian/lintian-overrides`) each give their reason.

Replacing fprintd's daemon: `libpam-fprintd` depends on `fprintd` at the same
version, so a `Provides: fprintd` cannot replace it. The package depends on
`fprintd` and diverts **only** fprintd's activation file
(`preinst`: `dpkg-divert --add --rename`, to
`net.reactivated.Fprint.service.fprintd`, a name dbus-daemon ignores). fprintd's
unit has no `[Install]` section, so once nothing activates it, it never starts.
`postinst` stops a running fprintd (it would hold the bus name), `postrm`
removes the diversion, which gives the file back to fprintd, and `purge`
removes `/var/lib/validity`. The unit is not enabled: D-Bus activation and the
udev rule start it, and an upgrade restarts it.

D-Bus offers no other way to take over an activation: the system bus only
activates from a file named after the bus name, and it searches
`/usr/local/share`, `/usr/share` and `/usr/lib` (`dbus-1/system-services`), in
that order, the first file found winning. Checked in the trixie container: no
directory a package may use comes before fprintd's.

### The CI cycle

`ci/packages/cycle.sh`, in a fresh trixie container booted with systemd
(`test` stage: fprintd, polkitd, curl and the system bus preinstalled):

1. snapshot every file (type, mode, SHA-256) outside volatile places;
2. `apt install ./validity-daemon_*.deb`, with the vendor download pointed at
   an unreachable address: the install must succeed and explain;
3. check the files, the diversion and the unit (`systemd-analyze verify`);
4. start `/usr/libexec/validity-daemon --fake-sensor` and run `fprintd-list`
   against it (`no fingers enrolled`);
5. let `fprintd-list` activate the installed daemon through D-Bus and systemd
   (`No devices available`: there is no sensor), and leave it running;
6. `apt purge`: the daemon is stopped, the diversion is gone, fprintd's file is
   back, and a second snapshot is identical to the first;
7. `fprintd-list` now activates fprintd itself.

`--fake-sensor` is a hidden daemon option (not in `--help`) for this cycle: the
emulated sensor of `validity_daemon::fake` replaces the USB one; everything else
is the production path.

**Containers never run privileged**, nor get host devices or host namespaces:
a privileged container sees the host's terminals, and a getty in it once hung
up the host's graphical session. systemd runs as PID 1 with a private cgroup
namespace, `CAP_SYS_ADMIN` and no seccomp/AppArmor profile only; the image
remounts its own cgroup namespace read-write before starting systemd, and masks
the getty, console and logind units. `ci/packages/run.sh` refuses
`--privileged`, `--device` and host namespaces, and checks
`HostConfig.Privileged` after starting each container. Without logind the
daemon logs that it has no sleep inhibitor and carries on.

### Reproducibility

`SOURCE_DATE_EPOCH` (the commit time) fixes every timestamp: the tarball, the
files in the package and the archive members. `ci/packages/run.sh repro` builds
the .deb twice from the same tarball and compares the files.

## The source tarball

`ci/packages/source.sh`: `git archive` of the tree (without `.github/` and
`fuzz/`), plus `vendor/` from `cargo vendor --locked` and a `.cargo/config.toml`
that points cargo at it. Builds then run with `--offline --locked`, every crate
checked against the checksums in `vendor/`. The tarball itself is reproducible
(sorted, fixed owner and mtimes, `gzip -n`).

## Tools and images

| Tool | Version | Checked |
|---|---|---|
| cargo-deb | 3.8.0 | crates.io, latest stable on 2026-10-24 |
| inno (crate) | 0.7.1 | crates.io, latest on 2026-10-24 |
| lintian | 2.122.0 | trixie |
| Rust | 1.99.1 | `rust:1.99.1-trixie`, pinned by digest |
| Debian | 13 (trixie) | `debian:trixie@sha256:4c25275446ca…`, pinned by digest |
