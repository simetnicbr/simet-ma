#!/bin/sh
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

INETUP=/opt/simet/bin/inetupc
REGISTER=/opt/simet/bin/simet_register_ma.sh
SIMETRUN=/opt/simet/bin/simet-ma_run.sh
USER=nicbr-simet

# do not mess with these unless you know what you are doing
[ -r /opt/simet/lib/simet/simet-ma.conf ] && . /opt/simet/lib/simet/simet-ma.conf
[ -r /opt/simet/etc/simet/simet-ma.conf ] && . /opt/simet/etc/simet/simet-ma.conf
AGENT_ID_FILE=${AGENT_ID_FILE:-/opt/simet/etc/simet/agent-id}
AGENT_TOKEN_FILE=${AGENT_TOKEN_FILE:-/opt/simet/etc/simet/agent.jwt}
SIMET_INETUP_SERVER=${SIMET_INETUP_SERVER:-simet-monitor-inetup.simet.nic.br}
BOOTID=$(cat /proc/sys/kernel/random/boot_id) || true

# first, ensure MA is registered
[ "$SIMET_REFRESH_AGENTID" = "true" ] && \
	rm -f "$AGENT_ID_FILE" "$AGENT_TOKEN_FILE"
$REGISTER --boot
echo "SIMET-MA: agent-id=$(cat $AGENT_ID_FILE)"
echo

# build inetup command, try to drop priviledges
INETUP_ARGS="-M ${LMAP_TASK_NAME_PREFIX}inetupc -b $BOOTID"
[ -r "$AGENT_TOKEN_FILE" ] && INETUP_ARGS="$INETUP_ARGS -j $(cat $AGENT_TOKEN_FILE)"
[ -r "$AGENT_ID_FILE" ] && INETUP_ARGS="$INETUP_ARGS -d $(cat $AGENT_ID_FILE)"
if [ $USER ] ; then
	INETUPCMD="sudo -u $USER -g $USER -H -n"
else
	INETUPCMD=
fi

[ "$SIMET_CRON_DISABLE" != "true" ] && [ -z "$SIMET_RUN_TEST" ] && [ -r /etc/cron.d/simet-ma ] && {
	echo "SIMET-MA: using cron to run measurements in background..."
	service cron start
	service cron status
	echo
	echo "SIMET-MA: cron configuration follows:"
	cat /etc/cron.d/simet-ma
	echo
}

[ "$SIMET_INETUP_DISABLE" != "true" ] && [ -z "$SIMET_RUN_TEST" ] && {
	echo "SIMET-MA: will execute the Internet Availability measurement (inetup)..."
	[ -n "$INETUP" ] && exec $INETUPCMD $INETUP $INETUP_ARGS $SIMET_INETUP_SERVER
	# not reached if inetup is run.
}

# We are not running inetup, so do a test run instead
if [ -n "$SIMET_RUN_TEST" ] ; then
	SIMET_RUN_TEST="--test $SIMET_RUN_TEST"
fi

exec $SIMETRUN $SIMET_RUN_TEST "$@"
:
