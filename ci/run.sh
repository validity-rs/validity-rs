#!/usr/bin/env bash
# The CI, runnable locally. GitHub Actions calls the same jobs, so a green local
# run means a green CI run.
#
#   ci/run.sh                 # quick: noai gitleaks fmt clippy test doc
#   ci/run.sh all             # quick + msrv deny distro e2e fuzz mutants-diff (needs docker)
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
ZIZMOR_VERSION=1.31.1
ZIZMOR_SHA256=d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99
CARGO_AUDIT_VERSION=0.22.2
CARGO_AUDIT_SHA256=7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428
# Keep in step with rust-version in Cargo.toml.
MSRV=1.99.0
# rust:1.99.0-trixie (Debian 13), pinned.
MSRV_IMAGE_DIGEST=sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90
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

tool_zizmor() {
    local a=zizmor-x86_64-unknown-linux-gnu.tar.gz
    fetch "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/$a" "$ZIZMOR_SHA256" "zizmor-$ZIZMOR_VERSION.tar.gz"
    [ -x "$CI_TOOLS/zizmor-$ZIZMOR_VERSION" ] || {
        tar -xzf "$CI_TOOLS/zizmor-$ZIZMOR_VERSION.tar.gz" -C "$CI_TOOLS" zizmor
        mv "$CI_TOOLS/zizmor" "$CI_TOOLS/zizmor-$ZIZMOR_VERSION"
    }
    echo "$CI_TOOLS/zizmor-$ZIZMOR_VERSION"
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
# Every finding fails, informational ones included.
job_zizmor() { "$(tool_zizmor)" --offline --persona=pedantic --min-severity=unknown .github/workflows; }
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
job_doc() { if use_image; then in_image debian cargo doc --workspace --no-deps; else cargo doc --workspace --no-deps; fi; }
# Tests, docs and the no-USB build run in the pinned Debian image when docker is
# there (CI always), on the host toolchain otherwise or with CI_HOST=1.
job_test() {
    if use_image; then in_image debian cargo test --workspace; return; fi
    command -v dbus-daemon >/dev/null || {
        echo "dbus-daemon is needed by validity-daemon's integration tests (Debian: apt install dbus-daemon)" >&2
        return 1
    }
    cargo test --workspace
}
job_msrv() {
    if [ -n "${CI_HOST:-}" ] && rustup toolchain list 2>/dev/null | grep -q "^$MSRV"; then
        cargo "+$MSRV" check --workspace --all-targets
    else
        docker run --rm -v "$PWD:/w" -w /w -e CARGO_TARGET_DIR=/tmp/t -e RUSTFLAGS -e RUSTDOCFLAGS \
            "rust:$MSRV-trixie@$MSRV_IMAGE_DIGEST" cargo check --workspace --all-targets
    fi
}
job_deny() { "$(tool_cargo_deny)" --all-features check; }
job_audit() { "$(tool_cargo_audit)" audit --deny warnings; }
job_distro() { local d; for d in "${@:-${DISTROS[@]}}"; do say "distro $d"; in_image "$d" cargo test --workspace; done; }
# The daemon with the emulated sensor behind a system bus and polkit, driven by
# fprintd's own clients and pam_fprintd (docker/Dockerfile.e2e, ci/e2e/run.sh).
# The protocol crate must build without its USB transport (that is what fuzzing uses).
job_nousb() {
    local c='cargo check -p validity-proto --no-default-features --all-targets'
    if use_image; then in_image debian "$c"; else $c; fi
}
# Every fuzz target, FUZZ_SECONDS each (default 30); any crash, timeout or OOM fails.
# Needs a nightly toolchain and cargo-fuzz.
# Every fuzz target, FUZZ_SECONDS each (default 30); a crash, timeout or OOM fails.
# Runs in the Debian nightly image (docker/Dockerfile.fuzz), or on a host with
# nightly and cargo-fuzz when CI_HOST=1.
job_fuzz() {
    # shellcheck disable=SC2016 # expanded by the inner shell, inside the container
    local loop='cd fuzz && for t in $(cargo +nightly fuzz list); do echo "== fuzz $t (${FUZZ_SECONDS}s)" && cargo +nightly fuzz run "$t" -j 2 -- -max_total_time="$FUZZ_SECONDS" -rss_limit_mb=2048 -timeout=5 || exit 1; done'
    export FUZZ_SECONDS=${FUZZ_SECONDS:-30}
    if use_image; then
        build_image fuzz && docker compose run --rm -T -e FUZZ_SECONDS fuzz sh -c "$loop"
    else
        sh -c "$loop"
    fi
}
# Mutation testing (cargo-mutants, in the Debian image), on the crates of
# MUTANTS_CRATES: every mutant must be caught, except those argued in
# .cargo/mutants.toml.
#   mutants        all their code (weekly, in MUTANTS_SHARD=k/n slices; and on demand)
#   mutants-diff   only their code changed since MUTANTS_BASE (default: the previous
#                  commit; an unknown base, as for a new branch, means the previous
#                  commit too), on every push
# MUTANTS_JOBS (default 2) mutants are built and tested at a time. A mutant that
# makes the tests hang is killed after cargo-mutants' timeout and counts as caught:
# its exit status 3 (timeouts, which it reports ahead of missed mutants) passes
# only when mutants.out/missed.txt is empty. Results: mutants.out/.
MUTANTS_CRATES=(validity-proto validity-daemon pam-validity)
mutants_run() {
    local args=() p rc=0
    for p in "${MUTANTS_CRATES[@]}"; do args+=(-p "$p"); done
    args+=(-j "${MUTANTS_JOBS:-2}" "$@")
    if use_image; then
        # The container runs as root: mutants.out goes back to the caller.
        in_image debian "cargo mutants --version && { cargo mutants ${args[*]}; rc=\$?; \
            chown -R $(id -u):$(id -g) mutants.out; exit \$rc; }" || rc=$?
    else
        cargo mutants "${args[@]}" || rc=$?
    fi
    if [ "$rc" -eq 3 ] && [ -f mutants.out/missed.txt ] && [ ! -s mutants.out/missed.txt ]; then
        echo "no mutant missed; $(wc -l < mutants.out/timeout.txt) made the tests hang (caught)"
        return 0
    fi
    return "$rc"
}
job_mutants() { mutants_run ${MUTANTS_SHARD:+--shard "$MUTANTS_SHARD"}; }
job_mutants-diff() {
    # In the tree, not in target/: the containers have their own target volume.
    local base=${MUTANTS_BASE:-HEAD~1} diff=mutants.diff
    git rev-parse --verify -q "$base^{commit}" >/dev/null || base=HEAD~1
    git diff "$base" HEAD -- '*.rs' > "$diff"
    if [ ! -s "$diff" ]; then echo "no Rust change since $base"; return 0; fi
    mutants_run --in-diff "$diff"
}
job_e2e() { in_image e2e ci/e2e/run.sh; }

QUICK=(noai zizmor gitleaks fmt clippy test doc nousb)
ALL=("${QUICK[@]}" msrv deny distro e2e fuzz mutants-diff)

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
