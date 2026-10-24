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
ci/packages/run.sh apt             # APT repository: install, then unattended upgrade
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

## APT repository

The repository Debian users install from, and through which unattended-upgrades
keeps validity-daemon current. It is published as a static tree on GitHub
Pages, from the `gh-pages` branch of `validity-rs/apt`, at
`https://validity-rs.github.io/apt`:

```
dists/trixie/{InRelease,Release,Release.gpg}    signed (ed25519 subkey, SHA-512)
dists/trixie/main/binary-amd64/Packages{,.gz,.xz}
pool/main/v/validity-daemon/validity-daemon_<version>_amd64.deb
pool/main/v/validity-rs-archive-keyring/validity-rs-archive-keyring_<version>_all.deb
validity-rs-archive-keyring.gpg                 the public key (bootstrap)
validity-rs.sources                             the APT source (bootstrap)
```

`ci/packages/apt-repo.sh` writes the tree from a set of .deb files (it is a
function of them: each publication rebuilds it) with `apt-ftparchive`, signs
`InRelease` and `Release.gpg`, and checks both signatures against the public key
users get. Release fields: `Origin: validity-rs`, `Label: validity-rs`,
`Suite`/`Codename: trixie`, `Components: main`, `Architectures: amd64`.

### On a user's machine

One package, `validity-rs-archive-keyring` (built by
`ci/packages/build-keyring.sh`, lintian clean), installs, like Debian's own
keyring packages:

| File | What |
|---|---|
| `/usr/share/keyrings/validity-rs-archive-keyring.gpg` | the key, outside apt's global trust |
| `/etc/apt/sources.list.d/validity-rs.sources` | the source, deb822, `Signed-By:` that keyring only |
| `/etc/apt/apt.conf.d/50validity-rs` | `Unattended-Upgrade::Origins-Pattern`: `origin=validity-rs,codename=${distro_codename},label=validity-rs` |

`Signed-By` scopes the key to this repository: it cannot sign for Debian or any
other source, and Debian's keys cannot sign for this one (the APT test checks
the latter). The two files in `/etc` are conffiles. Upgrades of the package
carry key rotations.

Bootstrap, once:

```bash
curl -fsSLO https://validity-rs.github.io/apt/validity-rs-archive-keyring.gpg
gpg --show-keys --with-fingerprint validity-rs-archive-keyring.gpg
#   must show 59CB F35F 3147 A424 BE25  DF07 8F4B 8482 B486 C8FD
sudo install -m 0644 validity-rs-archive-keyring.gpg /usr/share/keyrings/
sudo curl -fsSL -o /etc/apt/sources.list.d/validity-rs.sources \
    https://validity-rs.github.io/apt/validity-rs.sources
sudo apt update
sudo apt install validity-rs-archive-keyring validity-daemon unattended-upgrades
```

From then on `apt upgrade`, or unattended-upgrades on its own, brings new
versions.

### The key

| | Fingerprint | Expires |
|---|---|---|
| primary, ed25519, certify only | `59CBF35F3147A424BE25DF078F4B8482B486C8FD` | 2036-10-24 |
| signing subkey, ed25519 | `1272C48B1B8C9FC58C331C89F9CCE85370BBD5B9` | 2029-10-24 |

User ID: `validity-rs archive signing key <409744+pierre-warnier@users.noreply.github.com>`.
The public key is `packaging/apt/validity-rs-archive-keyring.gpg`.

Why ed25519: Debian's own trixie release key is ed25519, and trixie's apt
verifies with Sequoia's `sqv`, whose policy
(`/usr/share/apt/default-sequoia.config`) accepts it without an end date (it
retires RSA-2048 in 2030, DSA already). An RSA-4096 key would work too, but has
larger signatures and no advantage here.

The primary key never leaves the maintainer's offline copy (a GnuPG home
outside every repository; add a passphrase with `gpg --change-passphrase` and
keep a backup offline; its revocation certificate is in
`openpgp-revocs.d/`). CI only ever holds the **signing subkey**, exported with
a stub in place of the primary:

```bash
export GNUPGHOME=<offline GnuPG home>
gpg --armor --export-secret-subkeys '1272C48B1B8C9FC58C331C89F9CCE85370BBD5B9!' >APT_SIGNING_KEY.asc
gpg --list-packets APT_SIGNING_KEY.asc | grep gnu-dummy   # the primary is only a stub
# A GitHub environment "apt" that only tags may deploy to, holding the secret:
gh api -X PUT repos/validity-rs/validity-rs/environments/apt \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/validity-rs/validity-rs/environments/apt/deployment-branch-policies \
    -f name='v*' -f type=tag
gh secret set APT_SIGNING_KEY --env apt -R validity-rs/validity-rs <APT_SIGNING_KEY.asc
shred -u APT_SIGNING_KEY.asc
```

Rotation (the subkey expires in 2029, or at once if it leaks):

1. With the primary key, add a new signing subkey
   (`gpg --quick-add-key <primary> ed25519 sign <expiry>`), or extend the old one
   (`gpg --quick-set-expire <primary> <expiry> <subkey>`).
2. Export the public key again into `packaging/apt/validity-rs-archive-keyring.gpg`,
   add an entry to `packaging/apt/keyring/changelog`, release: the new keyring
   package reaches every machine through the repository, still signed by the
   old subkey.
3. Once that release is out, replace the `APT_SIGNING_KEY` secret with the new
   subkey. After a leak, also revoke the old subkey
   (`gpg --edit-key <primary>`, `key <n>`, `revkey`) and republish the key.

Losing the primary key means a new key, distributed by hand (the bootstrap
above), so its offline backup matters more than anything else here.

`Valid-Until` is not set in `Release`: it would protect against a replayed old
repository, but every client would stop updating if a scheduled re-signing ever
failed. That trade-off can be revisited once publication is routine.

### The APT test

`ci/packages/run.sh apt`, in CI:

1. Builds the .deb, and a rebuild at Debian revision 2 as "the next release".
2. In the build image, without network: makes a **throwaway key** laid out like
   the real one, builds the keyring package with it, and writes two
   repositories: `v1` (revision 1) and `v2` (revision 2).
3. Serves `v1` over HTTP from one container. A clean trixie with systemd (and
   nothing else) bootstraps from it as above, checks that Debian's key is
   refused for this repository, runs `apt update` (no warning allowed),
   `apt install validity-daemon`, and `fingerprint-settings` when its .deb is
   there (from the sibling repository's `dist/debian`, otherwise skipped with a
   notice), and installs unattended-upgrades.
4. Publishes `v2` on the server; `unattended-upgrade --dry-run` must list
   validity-daemon and change nothing, then `unattended-upgrade` must upgrade it
   to revision 2 and restart the running daemon.

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
