# validity-rs APT repository

**[Website](https://validity-rs.github.io/)** · [Driver and service](https://github.com/validity-rs/validity-rs) · [Fingerprints app](https://github.com/validity-rs/fingerprint-settings) · [APT repository](https://validity-rs.github.io/apt/) · [Tool reference](https://validity-rs.github.io/docs.html)

The signed APT repository of [validity-rs](https://github.com/validity-rs/validity-rs),
the Linux driver for Synaptics/Validity `06cb:009a` match-on-chip fingerprint
sensors, served at **https://validity-rs.github.io/apt**.

This branch is written by validity-rs's release workflow: every release
rebuilds and re-signs the whole tree. Do not edit it by hand; this README's
source is `packaging/apt/README.md` in validity-rs.

## Packages

| Package | What |
|---|---|
| `validity-daemon` | the fprintd-compatible fingerprint service and `validity-vendor`; also the optional `validity-fprint` PAM profile |
| `fingerprint-settings` | the Fingerprints app, one screen to register or remove your right index finger |
| `validity-rs-archive-keyring` | this repository's key, APT source and unattended-upgrades setting |

## Suites

| Suite | Release | Packages |
|---|---|---|
| `trixie` | Debian 13 | all three |
| `resolute` | Ubuntu 26.04 LTS | all three |
| `noble` | Ubuntu 24.04 LTS | no `fingerprint-settings`: GTK and libadwaita are too old |

amd64 only.

## Install

The key's fingerprint is
`59CB F35F 3147 A424 BE25  DF07 8F4B 8482 B486 C8FD` (ed25519; the
repository is signed by its subkey `1272 C48B 1B8C 9FC5 8C33  1C89 F9CC E853 70BB D5B9`).
Check it before trusting the key.

Debian 13 (trixie):

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

Ubuntu 26.04 (resolute) and 24.04 (noble), once their suites are published:
the same, with the source of your release, and without `fingerprint-settings`
on 24.04:

```bash
. /etc/os-release
sudo curl -fsSL -o /etc/apt/sources.list.d/validity-rs.sources \
    "https://validity-rs.github.io/apt/validity-rs-$VERSION_CODENAME.sources"
```

## What the keyring package does

`validity-rs-archive-keyring` takes over the two files of the bootstrap,
byte for byte, and keeps them current (key rotations come as package
upgrades):

| File | What |
|---|---|
| `/usr/share/keyrings/validity-rs-archive-keyring.gpg` | the key, outside APT's global trust |
| `/etc/apt/sources.list.d/validity-rs.sources` | the source, with `Signed-By:` this key only |
| `/etc/apt/apt.conf.d/50validity-rs` | lets unattended-upgrades install this repository's updates |

`Signed-By` scopes the key: it cannot sign for Debian, Ubuntu or any other
source, and their keys cannot sign for this one. With unattended-upgrades
installed, new versions install themselves; otherwise `apt upgrade` brings
them.

## Remove

```bash
sudo apt purge validity-daemon fingerprint-settings validity-rs-archive-keyring
```

fprintd gets its service back, the password keeps working, and purging the
keyring package removes the key, the source and the unattended-upgrades
setting.

## More

- Using the sensor, pairing, enrolment, login:
  [validity-rs README](https://github.com/validity-rs/validity-rs#readme).
- How the repository is built, signed and tested, and the key's management:
  [docs/packaging.md](https://github.com/validity-rs/validity-rs/blob/master/docs/packaging.md#apt-repository).
- Other distributions: packages on the
  [GitHub releases](https://github.com/validity-rs/validity-rs/releases).
- Issues: [validity-rs/validity-rs](https://github.com/validity-rs/validity-rs/issues).
