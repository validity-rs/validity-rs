#!/usr/bin/env bash
# The release gate (.github/workflows/release.yml): the tag names the version
# in Cargo.toml, and the CI and Packages workflows are green on this commit.
# Waits for them while they run (a tag is usually pushed right after its
# commit). Writes version= and prerelease= to $GITHUB_OUTPUT.
#
# Environment: GH_TOKEN, REPO (owner/name), SHA, REF_TYPE, REF_NAME,
# WAIT_MINUTES (default 120).
set -euo pipefail

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
prerelease=false
if [ "$REF_TYPE" = tag ]; then
    case "$REF_NAME" in
        "v$version") ;;
        "v$version"-*) prerelease=true ;;
        *)
            echo "tag $REF_NAME does not name version $version (Cargo.toml): expected v$version or v$version-<pre>" >&2
            exit 1
            ;;
    esac
fi
echo "version $version, prerelease $prerelease"

# Every run of the workflow on this commit, newest first: "status conclusion".
runs() {
    gh api "repos/$REPO/actions/runs?head_sha=$SHA&per_page=100" \
        --jq ".workflow_runs[] | select(.name == \"$1\") | \"\(.status) \(.conclusion)\""
}
deadline=$(($(date +%s) + ${WAIT_MINUTES:-120} * 60))
for wf in CI Packages; do
    while :; do
        r=$(runs "$wf")
        if printf '%s\n' "$r" | grep -q '^completed success$'; then
            echo "$wf: green on $SHA"
            break
        fi
        if [ -n "$r" ] && ! printf '%s\n' "$r" | grep -qv '^completed'; then
            echo "$wf on $SHA did not succeed:" >&2
            printf '%s\n' "$r" >&2
            exit 1
        fi
        [ "$(date +%s)" -lt "$deadline" ] || { echo "$wf on $SHA: no green run in time" >&2; exit 1; }
        echo "$wf: ${r:-not started} ... waiting"
        sleep 60
    done
done
{
    echo "version=$version"
    echo "prerelease=$prerelease"
} >>"${GITHUB_OUTPUT:-/dev/null}"
