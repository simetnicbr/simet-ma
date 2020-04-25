#!/bin/bash
# Execute a simet-ma SIMET2 agent in foreground
# Copyright (c) 2019,2020 NIC.br <medicoes@simet.nic.br>
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
# Dependencies:
#   sudo, simet-ma (curl, lsb-release...)
#
# Environment:
#   SIMET_INETUP_DISABLE  : set to true to disable inetup
#   SIMET_CRON_DISABLE    : set to true to disable crontabs
#   SIMET_REFRESH_AGENTID : set to true to force re-register on run
#   SIMET_RUN_TEST        : runs just the test in SIMET_RUN_TEST and exits
#                           implies SIMET_INETUP_DISABLE and
#                           SIMET_CRON_DISABLE
#
# Command line:
#   will be passed as-is to simet-runner in SIMET_RUN_TEST mode.
#   this will change in the future.

set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

# Normalize environment variables
[ -n "$SIMET_RUN_TEST" ] && {
	SIMET_CRON_DISABLE=true
	SIMET_INETUP_DISABLE=true
}

RC=1
abend() {
	echo "SIMET-MA: $*" >&2
	exit $RC
}

# Load in SIMET-MA defaults and lib functions
. /opt/simet/lib/simet/simet_lib.sh || abend "failed to load simet_lib component"

##
## Hook system
##
[ -r "$0.hooks" ] && . "$0.hooks"
simet_load_hooks docker_ma

_simet_ma_exit() {
	trap - SIGTERM SIGINT SIGQUIT
	echo "$0: stopping services..." >&2
	for i in $SMA_SERVICES ; do service "$i" stop || true ; done
	echo "$0: send SIGTERM to all processes... ">&2
	kill -s TERM -1 ; sleep 10
	echo "$0: exiting" >&2
	exit 0
}

simet_ma_trap_setup() {
	trap '_simet_ma_exit' SIGTERM SIGINT SIGQUIT
}

call_hook simet_ma_docker_ep_init

# Handle early issues with filesystem permissions on persistent volumes
SUSER=nicbr-simet
simet_ma_ephemeral_dirs() {
	mkdir -p -m 0770 /var/run/simet /var/lock/simet || abend "cannot create ephemeral dirs"
	chgrp $SUSER /var/run/simet /var/lock/simet || abend "cannot chgrp $SUSER the ephemeral dirs"
	chmod 0770 /var/run/simet /var/lock/simet || abend "cannot chmod 0770 the ephemeral dirs"
	:
}
simet_ma_docker_volume_prepare() {
	find /opt/simet \! \( -user root -o -user $SUSER \) -exec chown $SUSER:$SUSER {} \+
	find /opt/simet \! \( -group root -o -group $SUSER \) -exec chgrp $SUSER {} \+
	:
}
call simet_ma_ephemeral_dirs
call simet_ma_docker_volume_prepare

# update the system packages at start-up
# (security updates and SIMET engine updates, only)
simet_ma_docker_ep_update() {
	echo "SIMET-MA: checking for engine and security updates..."
	rm -f /etc/apt/apt.conf.d/54nicbr-unattended-upgrade-disable-distro
	apt-get -qq update && unattended-upgrades || true
}
simet_ma_docker_ep_postupdate() {
	# Disable unattended-updates for everything but SIMET packages,
	# due to procfs being half-broken inside a non-CAP_SYS_ADMIN container
	cat <<- SIMETMADOCKEREPPU > /etc/apt/apt.conf.d/54nicbr-unattended-upgrade-disable-distro
		#clear Unattended-Upgrade::Allowed-Origins;
		#clear Unattended-Upgrade::Origins-Pattern;
	SIMETMADOCKEREPPU
}
call simet_ma_docker_ep_update
call simet_ma_docker_ep_postupdate

# create virtual label for this instance
simet_ma_docker_vlabel_setup() {
	VLABEL=$(/opt/simet/bin/simet_create_vlabel.sh) || VLABEL=
	[ -n "$VLABEL" ] && {
		echo "SIMET-MA: agent virtual label is: $VLABEL" >&2
		logger -t simet-ma -p daemon.notice "SIMET-MA: agent virtual label is: $VLABEL" >/dev/null 2>&1 || true
	}
}
call simet_ma_docker_vlabel_setup

INETUP=/opt/simet/bin/inetupc
REGISTER=/opt/simet/bin/simet_register_ma.sh
SIMETRUN=/opt/simet/bin/simet-ma_run.sh

[ -z "$AGENT_ID_FILE" ]    && abend "missing AGENT_ID_FILE in config"
[ -z "$AGENT_TOKEN_FILE" ] && abend "missing AGENT_TOKEN_FILE in config"
[ -z "$LMAP_AGENT_FILE" ]  && abend "missing LMAP_AGENT_FILE in config"

call_hook simet_ma_docker_env_setup

# first, ensure MA is registered
simet_ma_docker_register() {
	[ "$SIMET_REFRESH_AGENTID" = "true" ] && \
		rm -f "$AGENT_ID_FILE" "$AGENT_TOKEN_FILE" "$LMAP_AGENT_FILE"

	ENVLIST=$(env | sed -n -e '/^SIMET/{s/=.*//;H}' -e '${x;s/\n/,/g;s/^,//;s/,$//;p}')
	echo "SIMET-MA: attempting agent registration..."
	while [ ! -s "$AGENT_ID_FILE" ] || [ ! -s "$AGENT_TOKEN_FILE" ] ; do
		sudo --preserve-env="$ENVLIST" -u $SUSER -g $SUSER -H -n $REGISTER -- --boot || {
			echo "SIMET-MA: agent registration failed, will retry in 120 seconds"
			sleep 120
		}
	done
	echo "SIMET-MA: agent-id=$(cat $AGENT_ID_FILE)"
}
call simet_ma_docker_register

# Handle and forward SIGQUIT, SIGTERM
SMA_SERVICES=
call simet_ma_trap_setup

if [ "$SIMET_CRON_DISABLE" != "true" ] ; then
	echo "SIMET-MA: starting in-container services..."
	service rsyslog start
	SMA_SERVICES="rsyslog $SMA_SERVICES"
	if [ -r /etc/cron.d/simet-ma ] ; then
		echo "SIMET-MA: starting cron to run management tasks in background..."
		service cron start
		SMA_SERVICES="cron $SMA_SERVICES"
	fi
	if [ "$SIMET_INETUP_DISABLE" != "true" ] ; then
		echo "SIMET-MA: starting inetup measurement service..."
		service simet-ma start
		SMA_SERVICES="simet-ma $SMA_SERVICES"
	fi
	echo "SIMET-MA: starting LMAP scheduler..."
	service simet-lmapd start
	SMA_SERVICES="simet-lmapd $SMA_SERVICES"
else
	if [ -n "$SIMET_RUN_TEST" ] ; then
		SIMET_RUN_TEST="--test $SIMET_RUN_TEST"
	fi
	exec $SIMETRUN $SIMET_RUN_TEST "$@"
fi

echo "SIMET-MA: measurement agent is ready"

# wait around, procesing signals.  It could be forever,
# but we do want to force a container restart every so often
# e.g. because we can only fully update with a restart
sleep 15d & wait $!
:
