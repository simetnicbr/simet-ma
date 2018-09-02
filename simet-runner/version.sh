#!/bin/sh
# Copyright (c) 2018 by NIC.br
# Public domain
#
# for one-level subprojects

GIT_VER=
ME=$(realpath -q -e "$0")
BME=$(dirname "$ME")

exiterr() {
	echo "unknown"
	exit 1
}

cd "$BME" || exiterr
if git rev-parse --git-dir >/dev/null 2>&1 ; then
	[ -n "$(git rev-parse --show-prefix 2>/dev/null)" ] && cd ..
	[ -z "$(git rev-parse --show-prefix 2>/dev/null)" ] && \
		GIT_VER=$(git describe --dirty=+ --abbrev=10 --tags --long --match 'v*' --always 2>/dev/null)
fi
[ -z "$GIT_VER" ] && GIT_VER=$(cat version 2>/dev/null || cat ../version 2>/dev/null)
[ -z "$GIT_VER" ] && exiterr
echo "$GIT_VER"
:
