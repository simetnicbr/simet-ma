#!/bin/sh
# Copyright (c) 2018 NIC.br
# Distributed under the GPLv2+

OUTFILE=
abend() {
	echo "$0: $*" >&2
	[ -n "$OUTFILE" ] && rm -f "$OUTFILE" 2>/dev/null
	exit 1
}

CFGDIR=/etc/simet
AIDFILE=$CFGDIR/agent-id
ATFILE=$CFGDIR/agent.jwt
APIGAT=https://api.lab.simet.nic.br/measurement/jwt

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
		"$APIGAT" ; do
			sleep 14400
	done
}

OLDAT=
OLDAID=
[ -r "$AIDFILE" ] && OLDAID=$(cat "$AIDFILE")
[ -r "$ATFILE" ]  && OLDAT=$(cat "$ATFILE")

OUTFILE=$(mktemp -q -t simet-at-register.$$.XXXXXXXXXX) || abend "failed to create tmpfile"
apicall || abend "failed to contact agent-token service"
SID=$(jsonfilter -i "$OUTFILE" -e "AID=@.agentId" -e "AT=@.token") || abend "illegal response from agent-token service"
rm -f "$OUTFILE"
eval "$SID" || abend "internal error"
[ x"$AID" != x"$OLDAID" ] && echo "$AID" > "$AIDFILE"
[ x"$AT"  != x"$OLDAT"  ] && echo "$AT" > "$ATFILE"

if [ ! -r "$AIDFILE" ] || [ -z "$AID" ] || [ ! -r "$ATFILE" ] || [ -z "$AT" ] ; then
	abend "$0: failed to register, please retry later"
fi

echo "$0: MA agent-id is $AID"
:
