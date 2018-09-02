#!/bin/sh
# Copyright (c) 2018 by NIC.br
# Public domain
#
# project top-level

GIT_VER=
ME=$(realpath -q -e "$0")
BME=$(dirname "$ME")

exiterr() {
	echo "unknown"
	exit 1
}

cd "$BME" || exiterr
if $(git rev-parse --git-dir >/dev/null 2>&1) && [ -z "$(git rev-parse --show-prefix 2>/dev/null)" ] ; then
	GIT_VER=$(git describe --dirty=+ --abbrev=10 --tags --long --match 'v*' --always 2>/dev/null)
fi
[ -z "$GIT_VER" ] && GIT_VER=$(cat version)
[ -z "$GIT_VER" ] && exiterr
echo "$GIT_VER"
:
