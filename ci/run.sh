#!/usr/bin/env bash
# The CI, runnable locally. GitHub Actions calls the same jobs, so a green local
# run means a green CI run.
#
#   ci/run.sh                 # quick: noai gitleaks fmt clippy test doc
#   ci/run.sh all             # quick + msrv deny distro (needs docker)
#   ci/run.sh clippy distro   # selected jobs
#   ci/run.sh distro:fedora   # one distro
#
# Tools that are not cargo subcommands are downloaded once, checked against a
# pinned SHA-256 and cached in $CI_TOOLS (default ~/.cache/validity-rs-ci).
# When bumping a version, bump its checksum with it.
set -euo pipefail

GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
CARGO_DENY_VERSION=0.20.2
CARGO_DENY_SHA256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
CARGO_AUDIT_VERSION=0.22.2
CARGO_AUDIT_SHA256=7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428
# Keep in step with rust-version in Cargo.toml.
MSRV=1.99.0
DISTROS=(debian fedora archlinux alpine)

cd "$(git rev-parse --show-toplevel)"
# No warning is tolerated: every cargo invocation, here and in the containers
# (docker-compose.yml passes these through), turns warnings into errors.
export RUSTFLAGS="-D warnings" RUSTDOCFLAGS="-D warnings"
CI_TOOLS=${CI_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/validity-rs-ci}
mkdir -p "$CI_TOOLS"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# fetch <url> <sha256> <file>: download into $CI_TOOLS once, verify every time.
fetch() {
    local url=$1 sum=$2 out="$CI_TOOLS/$3"
    [ -f "$out" ] || curl -fsSL --retry 5 --retry-all-errors -o "$out.part" "$url" && { [ -f "$out" ] || mv "$out.part" "$out"; }
    echo "$sum  $out" | sha256sum -c --quiet -
}

tool_gitleaks() {
    local a="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$a" "$GITLEAKS_SHA256" "$a"
    [ -x "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION" ] || {
        tar -xzf "$CI_TOOLS/$a" -C "$CI_TOOLS" gitleaks
        mv "$CI_TOOLS/gitleaks" "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION"
    }
    echo "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION"
}

tool_cargo_deny() {
    local n="cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl"
    fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/$n.tar.gz" "$CARGO_DENY_SHA256" "$n.tar.gz"
    [ -x "$CI_TOOLS/$n/cargo-deny" ] || tar -xzf "$CI_TOOLS/$n.tar.gz" -C "$CI_TOOLS" "$n/cargo-deny"
    echo "$CI_TOOLS/$n/cargo-deny"
}

tool_cargo_audit() {
    local n="cargo-audit-x86_64-unknown-linux-musl-v${CARGO_AUDIT_VERSION}"
    fetch "https://github.com/rustsec/rustsec/releases/download/cargo-audit/v${CARGO_AUDIT_VERSION}/$n.tgz" "$CARGO_AUDIT_SHA256" "$n.tgz"
    [ -x "$CI_TOOLS/$n/cargo-audit" ] || tar -xzf "$CI_TOOLS/$n.tgz" -C "$CI_TOOLS" "$n/cargo-audit"
    echo "$CI_TOOLS/$n/cargo-audit"
}

# Image builds pull from public registries: retry transient failures only.
build_image() {
    local attempt
    for attempt in 1 2 3; do
        docker compose build -q "$1" && return 0
        [ "$attempt" -lt 3 ] && { echo "image $1: build attempt $attempt failed, retrying in 30s" >&2; sleep 30; }
    done
    return 1
}

in_image() { local img=$1; shift; build_image "$img" && docker compose run --rm -T "$img" sh -c "rustc --version && $*"; }

job_noai() { bash .github/scripts/no-ai-traces.sh HEAD; }
job_gitleaks() { "$(tool_gitleaks)" git --redact --exit-code 1 --no-banner .; }
# fmt and clippy use the pinned Debian image when docker is there, so the lint set
# only moves with a reviewed image bump. CI_HOST=1 (the pre-push hook) uses the
# host toolchain instead, for speed.
use_image() { [ -z "${CI_HOST:-}" ] && command -v docker >/dev/null; }
job_fmt() { if use_image; then in_image debian cargo fmt --all --check; else cargo fmt --all --check; fi; }
job_clippy() {
    local c='cargo clippy --workspace --all-targets -- -D warnings'
    if use_image; then in_image debian "$c"; else $c; fi
}
job_doc() { cargo doc --workspace --no-deps; }
job_test() { cargo test --workspace; }
job_msrv() {
    if rustup toolchain list 2>/dev/null | grep -q "^$MSRV"; then
        cargo "+$MSRV" check --workspace --all-targets
    else
        docker run --rm -v "$PWD:/w" -w /w -e CARGO_TARGET_DIR=/tmp/t -e RUSTFLAGS -e RUSTDOCFLAGS "rust:$MSRV-trixie" cargo check --workspace --all-targets
    fi
}
job_deny() { "$(tool_cargo_deny)" --all-features check; }
job_audit() { "$(tool_cargo_audit)" audit --deny warnings; }
job_distro() { local d; for d in "${@:-${DISTROS[@]}}"; do say "distro $d"; in_image "$d" cargo test --workspace; done; }

QUICK=(noai gitleaks fmt clippy test doc)
ALL=("${QUICK[@]}" msrv deny distro)

jobs=("$@")
[ ${#jobs[@]} -eq 0 ] && jobs=("${QUICK[@]}")
[ "${jobs[*]}" = all ] && jobs=("${ALL[@]}")

failed=()
for j in "${jobs[@]}"; do
    name=${j%%:*}
    arg=${j#*:}; [ "$arg" = "$j" ] && arg=
    if ! declare -F "job_$name" >/dev/null; then echo "unknown job: $j" >&2; exit 2; fi
    say "$j"
    if ! "job_$name" ${arg:+"$arg"}; then failed+=("$j"); fi
done

if [ ${#failed[@]} -gt 0 ]; then
    printf '\n\033[31mFAILED: %s\033[0m\n' "${failed[*]}"
    exit 1
fi
printf '\n\033[32mOK: %s\033[0m\n' "${jobs[*]}"
