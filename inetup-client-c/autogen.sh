#!/bin/sh
#
# Commands required to prepare tree for building after
# a clean checkout
#
# Embedded libubox build dependencies:
#    libjson-c-dev
#    liblua5.1-dev
#    cmake
#
# Main project build dependencies
#    autoconf, automake, libtool (newer possible)

./version.sh >/dev/null 2>&1 || {
	echo "$0: missing version file and not in a worktree" >&2
	exit 1
}
autoreconf -i
