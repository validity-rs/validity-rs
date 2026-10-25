#!/usr/bin/env bash
# The APT source of one suite (ci/packages/suites.sh), from the template
# packaging/apt/validity-rs.sources, on standard output. The keyring package
# installs it and the repository root carries it for the bootstrap.
#   apt-sources.sh <packaging dir> <suite>
set -euo pipefail
# shellcheck source=suites.sh
. "$(dirname "$0")/suites.sh"

release=$(suite_release "$2")
sed -e "s/@SUITE@/$2/" -e "s/@RELEASE@/$release/" "$1/apt/validity-rs.sources"
