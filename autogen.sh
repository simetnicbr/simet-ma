#!/bin/sh
#
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
#
#
# Commands required to prepare tree for building after a clean
# checkout:
#
# Embedded libubox/jsonpath build dependencies:
#   libjson-c-dev cmake
#
# Main project build dependencies:
#   autoconf, automake, libtool (recent versions!)

./version.sh >/dev/null 2>&1 || {
	echo "$0: missing version file and not in a worktree" >&2
	exit 1
}
autoreconf -i
