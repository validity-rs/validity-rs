#!/usr/bin/env bash
# Builds the RPM (and the source RPM) from the vendored source tarball with
# packaging/rpm/validity-daemon.spec and lints them, inside the Fedora build
# image with no network (ci/packages/run.sh fedora).
#   build-rpm.sh <tarball> <output dir>
set -euo pipefail

tarball=$1 out=$2
: "${SOURCE_DATE_EPOCH:?}"
name=$(basename "$tarball" .tar.gz)
version=${name#validity-rs-}
top=$(mktemp -d)
mkdir -p "$top"/{SOURCES,SPECS}
cp "$tarball" "$top/SOURCES/"
tar -xzOf "$tarball" "$name/packaging/rpm/validity-daemon.spec" >"$top/SPECS/validity-daemon.spec"
grep -qE "^Version: +$version\$" "$top/SPECS/validity-daemon.spec" || {
    echo "the spec's Version is not $version (Cargo.toml)" >&2
    exit 1
}
# Reproducible: build time and file times from SOURCE_DATE_EPOCH, fixed host.
rpmbuild -ba --define "_topdir $top" \
    --define "_buildhost reproducible" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_epoch 1" \
    "$top/SPECS/validity-daemon.spec"
mkdir -p "$out"
cp "$top"/RPMS/*/*.rpm "$top"/SRPMS/*.src.rpm "$out/"
rpm -qip "$out"/validity-daemon-"$version"-*.x86_64.rpm
rpm -qlvp "$out"/validity-daemon-"$version"-*.x86_64.rpm
rpm -qp --requires --provides --conflicts --scripts "$out"/validity-daemon-"$version"-*.x86_64.rpm
# rpmlint: errors fail; warnings are shown (Fedora's own packages carry some).
rpmlint "$top/SPECS/validity-daemon.spec" "$out"/*.rpm
echo "rpmlint: no errors"
