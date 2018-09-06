#!/bin/sh
#
# Commands required to prepare tree for building after
# a clean checkout
#
# Main project build dependencies
#    autoconf, automake

./version.sh >/dev/null 2>&1 || {
	echo "$0: missing version file and not in a worktree" >&2
	exit 1
}
autoreconf -i
