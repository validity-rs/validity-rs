# shellcheck shell=bash disable=SC2034 # SUITES is for the scripts that source this
# The APT suites, one per distribution release, sourced by the scripts that
# build, test and publish the .deb files (bash). Each suite's packages are
# built in that release's own container; its .deb files carry the suite in
# their Debian revision (none for Debian, ".ubuntu<version>" for Ubuntu), so
# that the files of every suite can share one directory (a GitHub release:
# GitHub renames "~" and "+" in file names, hence ".") and the repository
# knows which suite a .deb belongs to. fingerprint-settings uses the same
# suffixes.
#
#   suite      release                       revision suffix
#   trixie     Debian 13                     (none)
#   noble      Ubuntu 24.04 LTS              .ubuntu24.04
#   resolute   Ubuntu 26.04 LTS              .ubuntu26.04

SUITES=(trixie noble resolute)

# suite_suffix <suite>: the revision suffix of the suite's packages.
suite_suffix() {
    case "$1" in
        trixie) echo "" ;;
        noble) echo .ubuntu24.04 ;;
        resolute) echo .ubuntu26.04 ;;
        *) echo "unknown suite: $1" >&2; return 1 ;;
    esac
}

# suite_release <suite>: the release, for people.
suite_release() {
    case "$1" in
        trixie) echo "Debian 13 (trixie)" ;;
        noble) echo "Ubuntu 24.04 LTS (noble)" ;;
        resolute) echo "Ubuntu 26.04 LTS (resolute)" ;;
        *) echo "unknown suite: $1" >&2; return 1 ;;
    esac
}

# suite_of_version <package version>: the suite a package of that version
# belongs to; fails on a suffix no suite has.
suite_of_version() {
    case "$1" in
        *.ubuntu24.04) echo noble ;;
        *.ubuntu26.04) echo resolute ;;
        *.ubuntu*) echo "version $1: no suite for this Ubuntu release" >&2; return 1 ;;
        *) echo trixie ;;
    esac
}
