# validity-daemon for Fedora (COPR), built from the vendored source tarball
# (validity-rs-<version>.tar.gz: the sources and every crate they use), offline.
# Layout as on Debian (docs/packaging.md). fprintd stays installed (its tools,
# polkit actions and fprintd-pam are used); its unit is handed over to
# validity-daemon by a systemd drop-in, since RPM cannot divert a file.

# Release builds carry no debug information (as on Debian): no debuginfo
# subpackage. brp-strip still strips the binaries.
%global debug_package %{nil}

Name:           validity-daemon
Version:        0.1.0
Release:        1%{?dist}
Summary:        Fingerprint service for Synaptics/Validity match-on-chip sensors

# validity-rs is MIT. Statically linked crates: MIT, MIT OR Apache-2.0,
# Apache-2.0, BSD-3-Clause (subtle); see deny.toml.
License:        MIT AND Apache-2.0 AND BSD-3-Clause
URL:            https://github.com/validity-rs/validity-rs
Source0:        %{url}/releases/download/v%{version}/validity-rs-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo >= 1.99
BuildRequires:  rust >= 1.99
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
Requires:       fprintd
Requires:       polkit
Requires:       curl
Conflicts:      open-fprintd
Conflicts:      python3-validity
%{?systemd_requires}

%description
validity-daemon serves fprintd's D-Bus API (net.reactivated.Fprint) for the
Synaptics/Validity match-on-chip fingerprint sensors that libfprint does not
support (06cb:009a: ThinkPad T480, T480s, X280, X1 Carbon 6th gen).
fprintd-pam, the tools of fprintd and desktops keep working unchanged. PAM is
not configured by this package. The Synaptics vendor files, which may not be
redistributed, are downloaded on installation by validity-vendor and checked
by SHA-256.

%prep
%autosetup -n validity-rs-%{version}

%build
# Stripped by cargo: there is no debuginfo subpackage to move symbols to.
export CARGO_PROFILE_RELEASE_STRIP=symbols
cargo build --release --offline --locked -p validity-daemon -p validity-vendor

%install
install -Dpm0755 target/release/validity-daemon %{buildroot}%{_libexecdir}/validity-daemon
install -Dpm0755 target/release/validity-vendor %{buildroot}%{_sbindir}/validity-vendor
install -Dpm0644 packaging/common/systemd/validity-daemon.service %{buildroot}%{_unitdir}/validity-daemon.service
install -Dpm0644 packaging/common/systemd/fprintd.service.d/validity-daemon.conf \
    %{buildroot}%{_unitdir}/fprintd.service.d/validity-daemon.conf
install -Dpm0644 packaging/common/dbus-1/system.d/validity-daemon.conf \
    %{buildroot}%{_datadir}/dbus-1/system.d/validity-daemon.conf
install -Dpm0644 packaging/common/udev/60-validity-daemon.rules %{buildroot}%{_udevrulesdir}/60-validity-daemon.rules
install -Dpm0644 packaging/common/man/validity-vendor.8 %{buildroot}%{_mandir}/man8/validity-vendor.8
install -Dpm0644 packaging/common/metainfo/io.github.validity_rs.validity_daemon.metainfo.xml \
    %{buildroot}%{_metainfodir}/io.github.validity_rs.validity_daemon.metainfo.xml
install -Dpm0644 packaging/common/validity.toml.example \
    %{buildroot}%{_docdir}/%{name}/validity.toml.example
install -Dpm0644 README.md %{buildroot}%{_docdir}/%{name}/README.md

%post
%systemd_post validity-daemon.service
# A running fprintd would keep the bus name until it exits on its own.
systemctl stop fprintd.service >/dev/null 2>&1 || :
# The vendor files: downloaded once, checked by SHA-256. Offline, the
# installation still succeeds; the message says how to finish.
if ! validity-vendor install; then
    echo "validity-daemon: the vendor files are not installed yet (see above); the sensor stays" >&2
    echo "validity-daemon: unavailable until 'validity-vendor install' succeeds. Password login is unaffected." >&2
fi

%preun
%systemd_preun validity-daemon.service

%postun
%systemd_postun_with_restart validity-daemon.service
if [ "$1" -eq 0 ]; then
    # Removed, not upgraded: calibration and vendor files go too (the
    # enrolled fingerprints live on the sensor, not here).
    rm -rf %{_sharedstatedir}/validity
fi

%files
%license LICENSE NOTICE
%{_docdir}/%{name}/
%{_libexecdir}/validity-daemon
%{_sbindir}/validity-vendor
%{_unitdir}/validity-daemon.service
%dir %{_unitdir}/fprintd.service.d
%{_unitdir}/fprintd.service.d/validity-daemon.conf
%{_datadir}/dbus-1/system.d/validity-daemon.conf
%{_udevrulesdir}/60-validity-daemon.rules
%{_mandir}/man8/validity-vendor.8*
%{_metainfodir}/io.github.validity_rs.validity_daemon.metainfo.xml

%changelog
* Sat Oct 24 2026 validity-rs maintainers <409744+pierre-warnier@users.noreply.github.com> - 0.1.0-1
- First package.
