#!/bin/sh
# Copyright (c) 2018 NIC.br
# Distributed under the GPLv2+

OUTFILE=
abend() {
	logger -s -t simet-ma -p auth.err "$*"
	[ -n "$OUTFILE" ] && rm -f "$OUTFILE" 2>/dev/null
	exit 1
}

[ -r /etc/simet/simet-ma.conf ] && . /etc/simet/simet-ma.conf
AGENT_ID_FILE=${AGENT_ID_FILE:-/etc/simet/agent-id}
AGENT_TOKEN_FILE=${AGENT_TOKEN_FILE:-/etc/simet/agent.jwt}
AGENT_TOKEN_LOCK=${AGENT_TOKEN_LOCK:-/var/lock/simet-agent-token.lock}
API_AGENT_TOKEN=${API_AGENT_TOKEN:-https://api.simet.nic.br/measurement/jwt}

BOXID=$(get_mac_address.sh 2>/dev/null | tr A-F a-f | tr -d ': -') || true
BOXVERSION=$(get_simet_box_version.sh 2>/dev/null) || true
if [ -n "$BOXID" ] && [ -n "$BOXVERSION" ] ; then
	USERAGENT="-A SIMETBOX/$BOXVERSION"
fi

CURLOPT="-q -s -m 15 --max-filesize 4000 --retry 10 --retry-max-time 3600"

apicall() {
	until curl $CURLOPT $USERAGENT -H "X-SIMETBOX-ID: $BOXID" \
		-X POST -f -L -j -o "$OUTFILE" \
		-d simetAT="$OLDAT" -d "deviceInfo=$USERAGENT" \
		"$API_AGENT_TOKEN" ; do
			sleep 14400
	done
}

gettoken() {
	OLDAT=
	OLDAID=
	[ -r "$AGENT_ID_FILE" ] && OLDAID=$(cat "$AGENT_ID_FILE")
	[ -r "$AGENT_TOKEN_FILE" ] && OLDAT=$(cat "$AGENT_TOKEN_FILE")

	OUTFILE=$(mktemp -q -t simet-at-register.$$.XXXXXXXXXX) || abend "failed to create tmpfile"
	apicall || abend "failed to contact agent-token service"
	SID=$(jsonfilter -i "$OUTFILE" -e "AID=@.agentId" -e "AT=@.token") || abend "illegal response from agent-token service"
	rm -f "$OUTFILE"
	eval "$SID" || abend "internal error"
	[ x"$AID" != x"$OLDAID" ] && echo "$AID" > "$AGENT_ID_FILE"
	[ x"$AT"  != x"$OLDAT"  ] && echo "$AT" > "$AGENT_TOKEN_FILE"

	if [ ! -r "$AGENT_ID_FILE" ] || [ -z "$AID" ] || [ ! -r "$AGENT_TOKEN_FILE" ] || [ -z "$AT" ] ; then
		abend "failed to register, please retry later"
	fi

	logger -s -t simet-ma -p auth.info "SIMET: LMAP measurement agent id: $AID"
	:
}

( flock -x 9 && gettoken ) <&- 9>> "$AGENT_TOKEN_LOCK"
