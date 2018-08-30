#!/bin/sh
# Copyright (c) 2018 by NIC.br
# Public domain

abend() {
	echo "$0: $*" >&2
	exit 1
}

GIT_VER=
if [ -r version ] ; then
	GIT_VER=$(cat version)
else
	git rev-parse --git-dir >/dev/null 2>&1 && GIT_VER=$(git describe --dirty=+ --abbrev=10 --tags --long --match 'v*' --always 2>/dev/null)
fi

if [ -n "$GIT_VER" ] ; then
	echo $GIT_VER
else
	echo "unknown"
	exit 1
fi
:
