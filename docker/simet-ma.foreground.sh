#!/bin/bash
# Execute a simet-ma SIMET2 agent in foreground
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
#   will be passed as-is to simet-runner.

set -e
export DEBIAN_FRONTEND=noninteractive

##
## Hook system
##
[ -r "$0.hooks" ] &&
	. "$0.hooks"

is_call_implemented() {
	command -V "$1" > /dev/null 2>&1
}
call() {
	cmd="$1"
	shift
	if is_call_implemented "${cmd}_override" ; then
		"${cmd}_override" "$@"
        else
		"${cmd}" "$@"
	fi
}
call_hook() {
	cmd="$1"
	shift
	if is_call_implemented "${cmd}" ; then
		"${cmd}" "$@"
	fi
}

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
USER=nicbr-simet
simet_ma_ephemeral_dirs() {
	[ -d /var/run/simet ] || mkdir -p -m 0750 /var/run/simet
	chgrp $USER /var/run/simet
	:
}
simet_ma_docker_volume_prepare() {
	find /opt/simet \! \( -user root -o -user $USER \) -exec chown $USER:$USER {} \+
	find /opt/simet \! \( -group root -o -group $USER \) -exec chgrp $USER {} \+
	:
}
call simet_ma_ephemeral_dirs
call simet_ma_docker_volume_prepare

# update the system packages at start-up
# (security updates and SIMET engine updates, only)
simet_ma_docker_ep_update() {
	echo "SIMET-MA: checking for engine and security updates..."
	apt-get -qq update && unattended-upgrades || true
}
call simet_ma_docker_ep_update

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

# do not mess with these unless you know what you are doing
[ -r /opt/simet/lib/simet/simet-ma.conf ] && . /opt/simet/lib/simet/simet-ma.conf
[ -r /opt/simet/etc/simet/simet-ma.conf ] && . /opt/simet/etc/simet/simet-ma.conf
AGENT_ID_FILE=${AGENT_ID_FILE:-/opt/simet/etc/simet/agent-id}
AGENT_TOKEN_FILE=${AGENT_TOKEN_FILE:-/opt/simet/etc/simet/agent.jwt}
LMAP_AGENT_FILE=${LMAP_AGENT_FILE:-/opt/simet/etc/simet/lmap/agent-id.json}
SIMET_INETUP_SERVER=${SIMET_INETUP_SERVER:-simet-monitor-inetup.simet.nic.br}
BOOTID=$(cat /proc/sys/kernel/random/boot_id) || true

call_hook simet_ma_docker_env_setup

# first, ensure MA is registered
simet_ma_docker_register() {
	[ "$SIMET_REFRESH_AGENTID" = "true" ] && \
		rm -f "$AGENT_ID_FILE" "$AGENT_TOKEN_FILE" "$LMAP_AGENT_FILE"

	echo "SIMET-MA: attempting agent registration..."
	while [ ! -s "$AGENT_ID_FILE" ] || [ ! -s "$AGENT_TOKEN_FILE" ] ; do
		sudo -u $USER -g $USER -H -n $REGISTER || {
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

# build inetup command, try to drop priviledges
INETUP_ARGS="-M ${LMAP_TASK_NAME_PREFIX}inetconn-state -b $BOOTID"
[ -n "$AGENT_TOKEN_FILE" ] && INETUP_ARGS="$INETUP_ARGS -j $AGENT_TOKEN_FILE"
[ -n "$AGENT_ID_FILE" ] && INETUP_ARGS="$INETUP_ARGS -d $AGENT_ID_FILE"
INETUPCMD="sudo -u $USER -g $USER -H -n"

[ "$SIMET_CRON_DISABLE" != "true" ] && [ -z "$SIMET_RUN_TEST" ] && {
	service rsyslog start
	if [ -r /etc/cron.d/simet-ma ] ; then
		echo "SIMET-MA: starting cron to run management tasks in background..."
		service cron start
		SMA_SERVICES="cron ${SMA_SERVICES}"
	fi
	echo "SIMET-MA: starting LMAP scheduler..."
	service simet-lmapd start
	SMA_SERVICES="simet-lmapd ${SMA_SERVICES}"
}

if [ -z "$SIMET_RUN_TEST" ] ; then
	echo "SIMET-MA: main loop start."
	while true; do
		if [ "$SIMET_INETUP_DISABLE" != "true" ] && [ -n "$INETUP" ] ; then
			$INETUPCMD $INETUP $INETUP_ARGS $SIMET_INETUP_SERVER &
			wait $! && exit 0
			sleep 1
		else
			sleep 365d
		fi
	done
else
	# We are not running inetup, so do a test run instead
	exec $SIMETRUN --test $SIMET_RUN_TEST "$@"
fi
:
