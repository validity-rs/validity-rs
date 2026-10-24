#!/usr/bin/env bash
# Packages: build each one from the vendored source tarball in its pinned distro
# image (no network), then install, smoke-test and remove it in a fresh
# container of the same distro. .github/workflows/packages.yml calls this.
#
#   ci/packages/run.sh                 # source, every distro, repro, apt
#   ci/packages/run.sh debian          # one distro (builds the tarball if absent)
#   ci/packages/run.sh source          # only the vendored source tarball
#   ci/packages/run.sh apt             # APT repository from the .deb: apt install
#                                      # and unattended upgrade in a clean trixie
#   ci/packages/run.sh repro           # build the .deb twice, compare
#   ci/packages/run.sh keyring         # the keyring package, real public key
#   ci/packages/run.sh apttree         # the signed APT tree (release; needs
#                                      # APT_SIGNING_KEY and target/packages/apt-debs)
#
# Environment:
#   SOURCE_TREE     git tree-ish to package (default HEAD)
#   PKG_OUT         output directory (default target/packages)
#   PKG_CPUS        docker --cpuset-cpus for every container (local runs)
#   VENDOR_ONLINE=1 the cycles also download Lenovo's real package
#   KEEP_SOURCE=1   reuse an existing source tarball
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ROOT=$PWD
OUT=${PKG_OUT:-$ROOT/target/packages}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARBALL=validity-rs-$VERSION.tar.gz
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}
DISTROS=(debian fedora archlinux alpine)
CPUS=()
[ -n "${PKG_CPUS:-}" ] && CPUS=(--cpuset-cpus "$PKG_CPUS")

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# Containers and networks of this run, removed however it ends.
CONTAINERS=() NETWORKS=()
cleanup() {
    [ ${#CONTAINERS[@]} -eq 0 ] || docker rm -f "${CONTAINERS[@]}" >/dev/null 2>&1 || true
    [ ${#NETWORKS[@]} -eq 0 ] || docker network rm "${NETWORKS[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# image <distro> <build|test>: builds docker/Dockerfile.pkg-<distro> --target.
image() {
    local tag="validity-rs-pkg-$1-$2" attempt
    for attempt in 1 2 3; do
        if [ ${#CPUS[@]} -gt 0 ]; then
            # BuildKit has no CPU limit; the classic builder does.
            DOCKER_BUILDKIT=0 docker build -q "${CPUS[@]}" -f "docker/Dockerfile.pkg-$1" --target "$2" -t "$tag" docker >/dev/null
        else
            docker build -q -f "docker/Dockerfile.pkg-$1" --target "$2" -t "$tag" docker >/dev/null
        fi && { echo "$tag"; return 0; }
        echo "image $tag: attempt $attempt failed" >&2
        [ "$attempt" -lt 3 ] && sleep 30
    done
    return 1
}

# Files written by the containers (as root) go back to the caller.
own() { docker run --rm "${CPUS[@]}" -v "$OUT:/out" "$(image debian build)" chown -R "$(id -u):$(id -g)" /out; }

# build <distro> <script> [args]: runs ci/packages/<script> in the build image,
# offline, with the tarball and the output directory mounted.
build() {
    local d=$1 script=$2; shift 2
    local img; img=$(image "$d" build)
    docker run --rm "${CPUS[@]}" --network none \
        -v "$ROOT/ci/packages:/ci:ro" -v "$OUT:/out" \
        -e SOURCE_DATE_EPOCH -e CARGO_BUILD_JOBS \
        "$img" bash "/ci/$script" "/out/$TARBALL" "$@"
    own
}

# cycle <distro> <package path inside /out>: fresh container booted with its
# init system, the cycle script inside it.
# systemd runs as PID 1 in the test containers. It gets only what it needs, never
# --privileged or host devices: a privileged container sees the host's ttys, and its
# getty hung up the host's graphical session (SIGHUP to the compositor) twice.
SYSTEMD_CTR=(--cgroupns=private --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined)
if grep -nE -- '--privileged|--device[ =]|--pid[ =]host|--ipc[ =]host|--uts[ =]host' "${BASH_SOURCE[0]}" | grep -v '^[0-9]*:#' | grep -v 'grep -nE' >&2; then
    echo "ci/packages/run.sh: host-level container options are forbidden (see above)" >&2
    exit 2
fi

# not_privileged <container>: refuses to go on with a privileged container.
not_privileged() {
    [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$1")" = false ] || {
        echo "container $1 is privileged: refused" >&2
        docker rm -f "$1" >/dev/null
        exit 2
    }
}

cycle() {
    local d=$1 pkg=$2 img cid status=0
    img=$(image "$d" test)
    cid=$(docker run -d "${CPUS[@]}" "${SYSTEMD_CTR[@]}" \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        -v "$ROOT/ci/packages:/ci:ro" -v "$OUT:/out:ro" "$img")
    CONTAINERS+=("$cid")
    not_privileged "$cid"
    docker exec -e VENDOR_ONLINE "$cid" bash /ci/cycle.sh "$d" "$pkg" || status=$?
    [ "$status" -eq 0 ] || docker logs "$cid" 2>&1 | tail -30
    return "$status"
}

job_source() {
    if [ -n "${KEEP_SOURCE:-}" ] && [ -f "$OUT/$TARBALL" ]; then
        echo "kept $OUT/$TARBALL"
        return
    fi
    # The only step with network: cargo vendor.
    docker run --rm "${CPUS[@]}" -v "$ROOT:/src:ro" -v "$OUT:/out" \
        -v validity-rs-pkg-cargo:/usr/local/cargo/registry \
        -e OUT=/out -e SOURCE_TREE="${SOURCE_TREE:-HEAD}" -e SOURCE_DATE_EPOCH \
        -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
        -w /src "$(image debian build)" bash ci/packages/source.sh
    own
}
need_source() { [ -f "$OUT/$TARBALL" ] || job_source; }

job_debian() {
    need_source
    rm -rf "$OUT/debian"
    build debian build-deb.sh /out/debian
    cycle debian "/out/debian/validity-daemon_${VERSION}-1_amd64.deb"
}

job_fedora() {
    need_source
    rm -rf "$OUT/fedora"
    build fedora build-rpm.sh /out/fedora
    cycle fedora "$(cd "$OUT" && ls fedora/validity-daemon-"$VERSION"-*.x86_64.rpm | sed 's|^|/out/|')"
}

job_archlinux() {
    need_source
    rm -rf "$OUT/archlinux"
    build archlinux build-arch.sh /out/archlinux
    cycle archlinux "$(cd "$OUT" && ls archlinux/validity-daemon-"$VERSION"-*-x86_64.pkg.tar.zst | sed 's|^|/out/|')"
}

job_alpine() {
    need_source
    rm -rf "$OUT/alpine"
    build alpine build-apk.sh /out/alpine
    cycle alpine "$(cd "$OUT" && ls alpine/validity-daemon-"$VERSION"-r*.apk | sed 's|^|/out/|')"
}

# Reproducibility: the .deb built twice from the same tarball is the same file.
job_repro() {
    need_source
    local a b
    rm -rf "$OUT/repro"
    build debian build-deb.sh /out/repro/1
    build debian build-deb.sh /out/repro/2
    a=$(sha256sum "$OUT"/repro/1/*.deb | cut -d' ' -f1)
    b=$(sha256sum "$OUT"/repro/2/*.deb | cut -d' ' -f1)
    echo "build 1: $a"
    echo "build 2: $b"
    [ "$a" = "$b" ] || { echo "the two builds differ" >&2; return 1; }
}

# The APT repository: built from this .deb and a bumped rebuild, signed with a
# throwaway key, served over HTTP to a clean trixie that installs from it, then
# upgrades through unattended-upgrades once the next version is published.
# fingerprint-settings joins when its .deb is at FINGERPRINT_SETTINGS_DEBS
# (default: the sibling repository's dist/debian).
job_apt() {
    need_source
    [ -f "$OUT/debian/validity-daemon_${VERSION}-1_amd64.deb" ] || {
        rm -rf "$OUT/debian"
        build debian build-deb.sh /out/debian
    }
    rm -rf "$OUT/apt-next" "$OUT/apt" "$OUT/extra"
    # The "next release": same sources, Debian revision 2.
    build debian build-deb.sh /out/apt-next 2
    local fs=${FINGERPRINT_SETTINGS_DEBS:-$ROOT/../fingerprint-settings/dist/debian}
    if ls "$fs"/fingerprint-settings_*_amd64.deb >/dev/null 2>&1; then
        mkdir -p "$OUT/extra"
        cp "$fs"/fingerprint-settings_*_amd64.deb "$OUT/extra/"
    else
        echo "NOTICE: no fingerprint-settings .deb in $fs; the APT test runs without it"
    fi
    docker run --rm "${CPUS[@]}" --network none \
        -v "$ROOT/ci/packages:/ci:ro" -v "$ROOT/packaging:/packaging:ro" -v "$OUT:/out" \
        -e SOURCE_DATE_EPOCH "$(image debian build)" bash /ci/apt-test-repo.sh /out
    own

    local net=validity-rs-apt-$$ server client status=0
    docker network create "$net" >/dev/null
    NETWORKS+=("$net")
    # The repository server: the published tree, swapped for the next one.
    # Copied, not preserved: fresh mtimes, so that If-Modified-Since sees the
    # new publication (the two trees are written within the same second).
    server=$(docker run -d "${CPUS[@]}" --network "$net" --network-alias apt-repo \
        --tmpfs /srv -v "$OUT/apt:/repos:ro" "$(image debian build)" \
        sh -c 'cp -R /repos/v1/. /srv/ && exec python3 -I -m http.server 8000 --directory /srv')
    client=$(docker run -d "${CPUS[@]}" --network "$net" "${SYSTEMD_CTR[@]}" \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        -v "$ROOT/ci/packages:/ci:ro" "$(image debian apt-client)")
    CONTAINERS+=("$server" "$client")
    not_privileged "$server"
    not_privileged "$client"
    {
        docker exec "$client" bash /ci/apt-client.sh install \
            && docker exec "$server" sh -c 'rm -rf /srv/* && cp -R /repos/v2/. /srv/' \
            && docker exec "$client" bash /ci/apt-client.sh upgrade
    } || status=$?
    [ "$status" -eq 0 ] || docker logs "$server" 2>&1 | tail -30
    return "$status"
}

# The release's keyring package, with the real public key
# (packaging/apt/validity-rs-archive-keyring.gpg).
job_keyring() {
    rm -rf "$OUT/keyring"
    docker run --rm "${CPUS[@]}" --network none \
        -v "$ROOT/ci/packages:/ci:ro" -v "$ROOT/packaging:/packaging:ro" -v "$OUT:/out" \
        -e SOURCE_DATE_EPOCH "$(image debian build)" \
        bash /ci/build-keyring.sh /packaging/apt/validity-rs-archive-keyring.gpg /out/keyring
    own
}

# The published APT tree (release workflow): every .deb in $OUT/apt-debs,
# signed with the subkey in APT_SIGNING_KEY, into $OUT/apt-tree.
job_apttree() {
    : "${APT_SIGNING_KEY:?}"
    rm -rf "$OUT/apt-tree"
    docker run --rm "${CPUS[@]}" --network none \
        -v "$ROOT/ci/packages:/ci:ro" -v "$ROOT/packaging:/packaging:ro" -v "$OUT:/out" \
        -e SOURCE_DATE_EPOCH -e APT_SIGNING_KEY "$(image debian build)" \
        bash /ci/apt-sign-tree.sh /out/apt-debs /out/apt-tree
    own
}

# One job per process: bash ignores set -e inside a function called from a
# `||` list, so a job run in-process would carry on past a failed step.
if [ "${1:-}" = --job ]; then
    "job_$2"
    exit
fi
jobs=("$@")
[ ${#jobs[@]} -eq 0 ] && jobs=(source "${DISTROS[@]}" repro apt)
for j in "${jobs[@]}"; do
    declare -F "job_$j" >/dev/null || { echo "unknown job: $j" >&2; exit 2; }
done
failed=()
for j in "${jobs[@]}"; do
    say "$j"
    bash "$ROOT/ci/packages/run.sh" --job "$j" || failed+=("$j")
done
if [ ${#failed[@]} -gt 0 ]; then
    printf '\n\033[31mFAILED: %s\033[0m\n' "${failed[*]}"
    exit 1
fi
printf '\n\033[32mOK: %s\033[0m\n' "${jobs[*]}"
