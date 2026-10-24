#!/usr/bin/env bash
# Publishes the workspace crates to crates.io in dependency order, skipping a
# version already there (.github/workflows/release.yml, crates-io job). The
# token comes from Trusted Publishing (CARGO_REGISTRY_TOKEN, short-lived); a
# crate's very first version cannot be published that way (docs/packaging.md).
set -euo pipefail

: "${CARGO_REGISTRY_TOKEN:?}"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
# validity-vendor and validity-daemon depend on validity-proto.
for crate in validity-proto validity-vendor validity-daemon; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -A 'validity-rs release (github.com/validity-rs/validity-rs)' \
        "https://crates.io/api/v1/crates/$crate/$version")
    if [ "$code" = 200 ]; then
        echo "$crate $version: already on crates.io, skipped"
        continue
    fi
    echo "$crate $version: publishing"
    # cargo waits until the new version is in the index before returning, so
    # the next crate resolves it.
    cargo publish --locked -p "$crate"
done
