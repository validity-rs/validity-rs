#!/usr/bin/env bash
# Writes the vendored source tarball every package is built from:
#   $OUT/validity-rs-<version>.tar.gz
# = the git tree (SOURCE_TREE, default HEAD) + vendor/ (cargo vendor --locked)
# + .cargo/config.toml pointing cargo at vendor/, so that a build needs no
# network (`cargo build --offline --locked`). Reproducible: fixed order, owner
# and mtimes (SOURCE_DATE_EPOCH, default the commit time), gzip without name
# or time. Runs in the Debian build image (ci/packages/run.sh source).
set -euo pipefail

OUT=${OUT:?}
SOURCE_TREE=${SOURCE_TREE:-HEAD}
cd "$(git rev-parse --show-toplevel)"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
name=validity-rs-$version
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git archive --format=tar --prefix="$name/" "$SOURCE_TREE" | tar -x -C "$work"
(
    cd "$work/$name"
    # Only what builds the packages: no CI-only or local material.
    rm -rf .github fuzz
    mkdir -p .cargo
    # stdout is the configuration; its progress lines are only shown on failure.
    cargo vendor --locked --versioned-dirs vendor >>.cargo/config.toml 2>"$work/vendor.log" \
        || { cat "$work/vendor.log" >&2; exit 1; }
)
mkdir -p "$OUT"
tar --sort=name --format=pax --mtime="@$SOURCE_DATE_EPOCH" --clamp-mtime \
    --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "$work" -cf - "$name" | gzip -n -9 >"$OUT/$name.tar.gz.part"
mv "$OUT/$name.tar.gz.part" "$OUT/$name.tar.gz"
echo "$OUT/$name.tar.gz"
sha256sum "$OUT/$name.tar.gz"
