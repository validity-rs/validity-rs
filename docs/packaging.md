# Packaging

Every package is built from one vendored source tarball, in a pinned container
of its distribution, without network. It is then installed, smoke-tested and
removed in a fresh container of the same distribution. `ci/packages/run.sh` does
all of it, locally and in GitHub Actions (`.github/workflows/packages.yml`).

```bash
ci/packages/run.sh                 # every job below
ci/packages/run.sh source          # the vendored source tarball
ci/packages/run.sh debian          # build, lintian, install/smoke/remove cycle
ci/packages/run.sh fedora          # the same with rpmbuild/rpmlint
ci/packages/run.sh archlinux       # makepkg/namcap
ci/packages/run.sh alpine          # abuild/apkbuild-lint, OpenRC
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
2. `apt install ./validity-daemon_*.deb` with `download.lenovo.com` resolving
   to 127.0.0.1 (`/etc/hosts`, so it holds whatever environment the package
   manager gives its scripts): the install must succeed and say it is offline;
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

## Fedora

`packaging/rpm/validity-daemon.spec`, built with `rpmbuild` in
`docker/Dockerfile.pkg-fedora` (Fedora 44, its own Rust 1.99.0, the same pinned
image as the CI's Fedora job) from the source tarball, offline; `rpmlint` must
report no error. Same layout as on Debian.

Replacing fprintd: Fedora's `fprintd-pam` requires `fprintd` at the same
version, so `Conflicts`/`Provides: fprintd` would remove PAM support, and RPM
cannot divert fprintd's activation file. That file starts `fprintd.service`
(`SystemdService=`), and on Fedora (dbus-broker) activation always goes through
systemd. So the package ships a drop-in,
`/usr/lib/systemd/system/fprintd.service.d/validity-daemon.conf`
(`packaging/common/systemd/fprintd.service.d/`), that turns `fprintd.service`
into a hand-over: `Requires=`/`After=validity-daemon.service`, a
`Type=oneshot` `/usr/bin/true` in place of fprintd, and a placeholder
`BusName=` (systemd refuses two units declaring one bus name, and an empty
`BusName=` does not clear it; activation follows the activation file's
`SystemdService=`, not `BusName=`). No file of fprintd's is
touched, `rpm -V fprintd` stays clean, fprintd's updates change nothing, and
removing the package removes the drop-in: fprintd is back. `%post` stops a
running fprintd and runs `validity-vendor install`; `%postun` on erase removes
`/var/lib/validity`. `Conflicts: open-fprintd, python3-validity`.

Firmware policy: the package contains no vendor material (it is MIT); the
Lenovo file is downloaded on the user's machine. **COPR** accepts that: its
rules ("What I can build in Copr", fedora-copr/copr
`doc/user_documentation.rst`, checked 2026-10-24) forbid uploading material one
has no right to distribute or under a licence Fedora does not allow, and state
that COPR packages need not follow the Packaging Guidelines. **RPM Fusion**
follows the Fedora Packaging Guidelines (rpmfusion.org/Contributors), which do
not let scriptlets download, and its `nonfree` section is for redistributable
software; there the download would have to become a manual step (the lpf
approach). So: COPR first, RPM Fusion later if wanted, without the `%post`
download. COPR builds need a COPR project and a token (see Releases).

## Arch Linux

`packaging/archlinux/PKGBUILD` and `validity-daemon.install`, built with
`makepkg` (as an unprivileged user) in `docker/Dockerfile.pkg-archlinux` (Arch's
own Rust), from the source tarball pinned by its sha256, offline; `namcap` must
report no error. The CI also writes the PKGBUILD for the AUR: the release URL
and the published tarball's sha256. Arch avoids `/usr/libexec`, so the daemon is
`/usr/lib/validity-daemon/validity-daemon` and the unit is rewritten to match.
fprintd is replaced as on Fedora (pacman cannot divert either; same drop-in).
`conflicts=(open-fprintd python-validity)`: both own the bus name. Publishing to
the AUR needs an AUR account and its SSH key (see Releases).

## Alpine

`packaging/alpine/APKBUILD`, an OpenRC script (`validity-daemon.initd`, under
`supervise-daemon`, restarted 5 times per 120 s at most) and install scripts,
built with `abuild` in `docker/Dockerfile.pkg-alpine`; `apkbuild-lint` must be
clean. Alpine 3.24's Rust is 1.96, below the workspace's 1.99, so CI builds
with the official Rust 1.99.1 toolchain for Alpine 3.24 (`abuild -d`); in
aports the package would wait for Alpine 3.25 (edge has 1.99.1). The package is
signed with a throwaway key in CI (the cycle installs it with
`--allow-untrusted`).

D-Bus activation and polkit on Alpine: both work (dbus 1.16, polkit 127), but
without systemd the bus starts the `Exec=` of the activation file itself, and
that file is fprintd's (apk cannot divert it, and taking it over with
`replaces=` would lose it for good on removal). So on Alpine validity-daemon is
an OpenRC service that must own `net.reactivated.Fprint` before any client asks:
`rc-update add validity-daemon default` (the post-install message says so; it
starts after `dbus` and before the display managers). If it is not running, a
client activates fprintd, which finds no supported sensor, and PAM falls back
to the password. `fprintd-pam` does not depend on `fprintd` on Alpine, but
fprintd's tools and polkit actions do, hence the dependency. The service is
stopped on removal by the `-openrc` subpackage's pre-deinstall script, which
apk runs while the OpenRC script still exists. The cycle starts
OpenRC's `dbus` service in a plain container (`tini` as PID 1, which reaps
`supervise-daemon`'s orphans as init does; under a non-reaping PID 1 the stop
would wait forever on a zombie), checks that the OpenRC service
owns the name and answers `fprintd-list`, and that removal gives fprintd's
activation back. No udev rule is shipped (it only starts a systemd unit).

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

## Releases

`.github/workflows/release.yml` runs on a tag `v<version>` (the version in
`Cargo.toml`), or `v<version>-<pre>` for a prerelease. `workflow_dispatch` is a
dry run: everything is built and checked, nothing is signed, attested or
published.

1. **Gate** (`ci/packages/release-check.sh`): the tag names Cargo.toml's
   version, and the CI and Packages workflows are green on the tagged commit
   (it waits for them while they run).
2. **One source tarball**, then every package built from it in its pinned image
   and run through its install cycle again; the .deb is rebuilt and compared
   (`repro`); the keyring package is built with the real public key.
3. **SHA256SUMS** over every file, signed (`SHA256SUMS.asc`) by the archive
   signing subkey in the `apt` environment and checked with `gpgv` against
   `packaging/apt/validity-rs-archive-keyring.gpg`. Without the secret a
   prerelease goes out unsigned with a warning; a release fails.
4. **Provenance**: `actions/attest-build-provenance` v4.2.2 (pinned by commit)
   attests every file, and each attestation is verified at once with
   `gh attestation verify`. GitHub only offers attestations to public
   repositories on the Free plan; `validity-rs/validity-rs` is public, so
   they work. Were it made private, a tag would fail at this step.
5. **A draft GitHub release** with all files. A maintainer reviews it and
   publishes it.
6. Publication jobs, each off until its repository variable is `1`:
   `CRATES_IO_PUBLISH`, `APT_PUBLISH`, `COPR_PUBLISH`, `AUR_PUBLISH`.

Files of a release: `validity-rs-<v>.tar.gz` (the vendored sources),
`validity-daemon_<v>-1_amd64.deb`, `validity-rs-archive-keyring_<date>_all.deb`,
`validity-daemon-<v>-1.fc44.x86_64.rpm` and its `.src.rpm`,
`validity-daemon-<v>-1-x86_64.pkg.tar.zst`, the three Alpine `.apk`
(daemon, `-openrc`, `-doc`), `validity-daemon-<v>-aur.tar.gz` (PKGBUILD pinned to
the tarball, `.SRCINFO`, install script), `validity-daemon-<v>-APKBUILD`,
`SHA256SUMS`, `SHA256SUMS.asc`. Check a download with:

```bash
gh attestation verify <file> --repo validity-rs/validity-rs
gpgv --keyring ./validity-rs-archive-keyring.gpg SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

A test tag exercises the whole chain without a real release:
`git tag -a v0.1.0-rc.1 -m 'validity-rs 0.1.0-rc.1' && git push origin v0.1.0-rc.1`
gives a draft prerelease (not visible to the public); delete the draft and the
tag afterwards (`gh release delete v0.1.0-rc.1 --cleanup-tag`).

### crates.io

Publication goes through Trusted Publishing (`rust-lang/crates-io-auth-action`
v1.0.6: an OIDC token exchanged for a short-lived crates.io token, revoked at the
end of the job; nothing is stored), crates in dependency order (validity-proto,
validity-vendor, validity-daemon), a version already published is skipped
(`ci/packages/publish-crates.sh`). Only final versions, never prereleases.

**The first version of each crate still needs an ordinary token.** crates.io
refuses to create a crate with a Trusted Publishing token: `publish.rs`
answers "Trusted Publishing tokens do not support creating new crates. Publish
the crate manually, first" (rust-lang/crates.io, `src/controllers/krate/publish.rs`,
checked at commit fbca83038e59, 2026-10-24), and a Trusted Publisher is
configured on an existing crate. So, once, after the publication audit:

1. On crates.io, make an API token with the `publish-new` scope and a short
   expiry; `cargo login`; `cargo publish -p validity-proto`, then
   `-p validity-vendor`, then `-p validity-daemon`; revoke the token.
2. For each crate, *Settings, Trusted Publishing*: GitHub, repository
   `validity-rs/validity-rs`, workflow `release.yml`, environment `crates-io`.
3. Create the `crates-io` environment (tags only, as `apt` below) and
   `gh variable set CRATES_IO_PUBLISH --body 1 -R validity-rs/validity-rs`.

### APT repository on GitHub Pages

The repository is `validity-rs/apt` (Pages is free for public repositories),
served from its `gh-pages` branch. The `apt` job rebuilds the tree from the
release's .deb files plus the latest fingerprint-settings release
(`ci/packages/run.sh apttree`), and commits it to that branch (history kept,
never forced) with that repository's deploy key. Setting it up, once:

```bash
# The repository, with a gh-pages branch.
gh repo create validity-rs/apt --public --description 'APT repository of validity-rs (Debian 13)'
d=$(mktemp -d) && cd "$d" && git init -q -b gh-pages
echo 'validity-rs APT repository: https://github.com/validity-rs/validity-rs/blob/master/docs/packaging.md' >README.md
touch .nojekyll && git add . && git commit -qm 'APT repository'
git remote add origin git@github.com:validity-rs/apt.git && git push -u origin gh-pages
# Pages from gh-pages.
gh api -X POST repos/validity-rs/apt/pages -f 'source[branch]=gh-pages' -f 'source[path]=/'
# A deploy key, writable, for that repository only. Deploy keys are off by
# default in the organisation: allow them first (organisation setting).
gh api -X PATCH orgs/validity-rs -F deploy_keys_enabled_for_repositories=true
ssh-keygen -q -t ed25519 -N '' -C 'validity-rs release workflow' -f apt_deploy
gh repo deploy-key add apt_deploy.pub -R validity-rs/apt --allow-write --title 'validity-rs release workflow'
# The "apt" environment of validity-rs/validity-rs: tags only, both secrets.
gh api -X PUT repos/validity-rs/validity-rs/environments/apt \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/validity-rs/validity-rs/environments/apt/deployment-branch-policies \
    -f name='v*' -f type=tag
gh secret set APT_DEPLOY_KEY --env apt -R validity-rs/validity-rs <apt_deploy
gh secret set APT_SIGNING_KEY --env apt -R validity-rs/validity-rs <APT_SIGNING_KEY.asc   # see "The key"
shred -u apt_deploy APT_SIGNING_KEY.asc
gh variable set APT_PUBLISH --body 1 -R validity-rs/validity-rs
```

The next tag then publishes. Check it from any trixie machine with the
bootstrap above.

### COPR and the AUR

COPR: a COPR project `validity-rs/validity-daemon` (Fedora account), its
`copr-cli` configuration as secret `COPR_CONFIG` of a `copr` environment, and
`COPR_PUBLISH=1`; each release's source RPM is then built there. AUR: an AUR
account, the package `validity-daemon` created by a first push of
`validity-daemon-<v>-aur.tar.gz`'s files, the account's SSH key as secret
`AUR_SSH_KEY` of an `aur` environment, and `AUR_PUBLISH=1`. Both hosts' keys
are pinned in the workflow (GitHub's from `api.github.com/meta`, the AUR's
matching the fingerprint published on aur.archlinux.org).

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
| Fedora | 44 | `fedora:latest@sha256:43b29f65a41e…` (as the CI's Fedora job) |
| Arch Linux | rolling | `archlinux:base@sha256:52dfbd5afb23…` (as the CI's Arch job) |
| Alpine | 3.24.3 | `alpine:3.24.3@sha256:be2656061b53…`; build: `rust:1.99.1-alpine3.24@sha256:b1d5dd5a22a0…` |
