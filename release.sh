#! /bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set -e

_ESC=$'\e'
GREEN="$_ESC[0;32m"
MAGENTA="$_ESC[0;35m"
RED="$_ESC[0;31m"
LTCYAN="$_ESC[1;36m"
YELLOW="$_ESC[1;33m"
NORM="$_ESC[0;0m"

fail() {
    echo "${RED}${@}${NORM}"
    exit 1
}

status() {
    echo "${LTCYAN}-- ${*} --${NORM}"
}

message() {
    echo "${MAGENTA} ${*}${NORM}"
}

usage() {
    fail "USAGE: release.sh newversion"
}

[ $# = 1 ] || usage
[ -f release.sh ] || usage
newversion="${1}"
[ -z "$VIRTUAL_ENV" ] && fail "Need an activated virtualenv with fwunit installed"

status "tagging"

git tag -f $newversion
git log -1 --decorate $newversion

status "building docs to verify"

if ! sphinx-build docs build; then
    fail "building docs failed"
fi

status "building sdist"

python setup.py sdist

message "if everything looks OK,"
message " - git push --tags upstream"
message " - twine upload dist/fwunit-$newversion.tar.gz"
