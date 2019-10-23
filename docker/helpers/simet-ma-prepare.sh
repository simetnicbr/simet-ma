#!/bin/bash
# Prepares the simet-ma runtime image, helper script
# Copyright (c) 2019 NIC.br <medicoes@simet.nic.br>
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

set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive
SMAUSER=nicbr-simet

system_prepare() {
  ls /etc/apt/sources.list.d/*template >/dev/null 2>&1 || {
    echo "Missing /etc/apt/sources.list.d/*template" >&2
    exit 1
  }
  command -v lsb_release >/dev/null || {
    echo "Missing lsb-release package" >&2
    exit 1
  }

  CODENAME=$( lsb_release -sc )
  DISTRO=$( lsb_release -si | tr A-Z a-z )
  sed -e "s/@codename@/${CODENAME}/g" -e "s/@distro@/${DISTRO}/g" \
         < /etc/apt/sources.list.d/*.template \
         > /etc/apt/sources.list.d/nicbr-simet.apt.source.list
  rm -f /etc/apt/sources.list.d/*.template
  echo "$0: enabled required NIC.br package repositories for ${CODENAME} / ${DISTRO}" >&2

  echo "$0: updating list of available packages..." >&2
  apt-get -qq update
}

simet_ma_install() {
  echo "$0: updating system components and installing simet-ma..." >&2
  apt-get -q -y dist-upgrade \
    && apt-get -q -y install --install-recommends simet-ma \
    && return 0

  echo "$0: failed to install simet-ma" >&2
  exit 1
}

simet_ma_setup() {
  # Cleanup configuration that must not be present in a reference image
  echo "$0: removing SIMET-MA persistent data (for reference image)..." >&2
  rm -f /opt/simet/etc/simet/agent-id* /opt/simet/etc/simet/agent*.jwt \
        /opt/simet/etc/simet/agent-vlabel \
        /opt/simet/etc/simet/lmap/agent-id.json /opt/simet/etc/simet/lmap/group-id.json
}

system_prepare \
&& simet_ma_install \
&& simet_ma_setup \
&& {
  echo "$0: SIMET-MA installation into container successfull" >&2
  exit 0
}

echo "SIMET-MA installation failed" >&2
exit 1
