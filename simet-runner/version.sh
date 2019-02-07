#!/bin/sh
# one-level subproject version handler
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.  In every case, additional
# restrictions and permissions apply, refer to the COPYING file in the
# program Source for details.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License and the COPYING file in the program Source
# for details.

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
