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

autoreconf -i
./version.sh > version
