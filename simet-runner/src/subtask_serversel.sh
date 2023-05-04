#shellcheck shell=ash
# Copyright (c) 2023 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# Runs latency-based server selection using TWAMP-light against the
# possible "locations".
#
# function subtask_serverselection()
#  - input var: AGENT_ID, AGENT_TOKEN
#  - input data: services.json, twampquick_parameters.json
#  - output var: GLOBAL_STATE_PEER_IDXMAP
#
# Dependencies:
# - jsonfilter (default installed at OpenWRT) as $JSONFILTER
#
################################################################################

_twquick() {
  local tw_tag="$1"
  local tw_host="$2"

  log_verbose "server selection: peer #$tw_tag: $tw_host, TWAMP light measurement"
  "$TWAMPC" -m light -qq -R summary -O "$BASEDIR/twlight_result_${tw_tag}.json" \
      -c "$TWQUICK_PKTCOUNT" \
      -i "$TWQUICK_PKTDELAY" \
      -T "$TWQUICK_PKTTIMEOUT" \
      -p "$TWQUICK_REMOTEPORT" \
      -k "$TWQUICK_KEY" \
      "$tw_host"
}

_twquick_wait() {
  local _twpid="$1"
  local _peer_id="$2"
  wait "$_twpid" || {
    log_debug "server selection: peer #$_peer_id discarded: twamp client returned status $?"
    return 1
  }
  [ -s "$BASEDIR/twlight_result_$_peer_id.json" ] || {
    log_debug "server selection: peer #$_peer_id discarded: no/empty result file"
    return 1
  }
  local j
  j=$("$JSONFILTER" -i "$BASEDIR/twlight_result_$_peer_id.json" \
    -e "PKTSENT=@.results_summary.packets_sent" \
    -e "PKTDROP=@.results_summary.packets_lost" \
    -e "PKTRCVD=@.results_summary.packets_received_valid" ) || {
    log_debug "server selection: incorrect or missing data in results for peer #$_peer_id"
    return 1
  }
  eval "$j" || return 1
  # shellcheck disable=SC2015
  [ "$PKTSENT" -eq "$TWQUICK_PKTCOUNT" ] 2>/dev/null && [ "$PKTDROP" -le "$TWQUICK_DROPLIMIT" ] 2>/dev/null || {
    log_verbose "server selection: peer #$_peer_id dropped too many packets, discarded"
    return 1
  }
  # shellcheck disable=SC2015
  MEDIANRTT=$("$JSONFILTER" -i "$BASEDIR/twlight_result_$_peer_id.json" \
      -e "@.results_summary.rtt.rtt_median_us" ) && [ "$MEDIANRTT" -ge 0 ] 2>/dev/null || {
    log_debug "server selection: peer #$_peer_id missing or invalid median RTT, discarded"
    return 1
  }
  :
}

subtask_serverselection() {
  local _services="$BASEDIR/services.json"

  [ -s "$_services" ] || return
  [ -s "$BASEDIR/twampquick_parameters.json" ] || return
  [ -x "$TWAMPC" ] || return

  local j
  j=$("$JSONFILTER" -i "$BASEDIR/twampquick_parameters.json" \
    -e 'TWQUICK_PAYLOADSIZE=@.twamp_payload_size' \
    -e 'TWQUICK_PKTCOUNT=@.twamp_packet_count' \
    -e 'TWQUICK_PKTDELAY=@.twamp_packet_delay_us' \
    -e 'TWQUICK_PKTTIMEOUT=@.twamp_packet_timeout_us' \
    -e 'TWQUICK_REMOTEPORT=@.reflector_port' \
    -e 'TWQUICK_KEY=@.auth_key_base64') || return
  eval "$j" || return
  TWQUICK_DROPLIMIT=$("$JSONFILTER" -i "$BASEDIR/twampquick_parameters.json" \
    -e '@.twamp_packet_drop_limit') || TWQUICK_DROPLIMIT=1

  log_info "server selection: measuring network roundtrip time to the available servers..."
  log_debug "server selection: latency-based: send and receive $TWQUICK_PKTCOUNT packets in $TWQUICK_PKTTIMEOUT microseconds"

  local SCNT
  local S_PUBPEER
  local S_HOST

  local PEERPIDLIST=
  local PEERIDXLIST=
  local FBIDXLIST=
  SCNT=0
  while "$JSONFILTER" -i "$_services" -t "@[$SCNT]" >/dev/null 2>&1 ; do
    j=$("$JSONFILTER" -i "$_services" -e "S_PUBPEER=@[$SCNT].isPublicPeer" -e "S_HOST=@[$SCNT].twamp[0].hostname") || j=
    [ -n "$j" ] && {
      eval "$j" || return
      if [ "$S_PUBPEER" -eq 0 ] && [ -n "$S_HOST" ] ; then
	_twquick "$SCNT" "$S_HOST" 2>/dev/null & TWLPID=$!
	PEERPIDLIST=$(append_list "$PEERPIDLIST" "$TWLPID")
	PEERIDXLIST=$(append_list "$PEERIDXLIST" "$SCNT")
      elif [ -n "$S_HOST" ] ;  then
	log_verbose "server selection: peer #$SCNT: $S_HOST, global last-choice peer"
	FBIDXLIST=$(append_list "$FBIDXLIST" "$SCNT")
      fi
    }
    SCNT=$(( SCNT + 1 ))
  done

  # do we even have any work to do?
  [ -z "$PEERPIDLIST" ] && return

  local i
  local RESIDX=
  local RESRTT=
  local WIDXLIST="$PEERIDXLIST"
  local PCNT
  PCNT=0
  #log_debug "waiting for twamp client PIDs $PEERPIDLIST"
  for i in $PEERPIDLIST ; do
    WIDX="${WIDXLIST%% *}"
    WIDXLIST="${WIDXLIST#* }"
    if _twquick_wait "$i" "$WIDX" ; then
      log_verbose "server selection: peer #$WIDX: network RTT is approximately $MEDIANRTT microseconds"
      RESIDX=$(append_list "$RESIDX" "$WIDX")
      RESRTT=$(append_list "$RESRTT" "$MEDIANRTT")
      PCNT=$(( PCNT + 1 ))
    fi
  done

  [ -z "$RESIDX" ] || [ -z "$RESRTT" ] || [ "$PCNT" -eq 0 ] && {
    log_info "server selection: latency-based selection failed, using alternative selection method"
    return
  }

  # order by latency
  #log_debug "server selection: before sort: PCNT=$PCNT RESRTT='$RESRTT' RESIDX='$RESIDX'"
  i=$(while [ "$PCNT" -gt 0 ] ; do
	printf "%s :%d\n" "${RESRTT%% *}" "${RESIDX%% *}"
	RESRTT="${RESRTT#* }"
	RESIDX="${RESIDX#* }"
	PCNT=$(( PCNT - 1 ))
      done | sort -n | cut -d ':' -f 2 | tr -s '\n\r' ' ' | sed -e 's/^[ \t\n]*//' -e 's/[ \t\n]*$//') || {
    log_debug "server selection: failed to sort by latency."
    return
  }
  GLOBAL_STATE_PEER_IDXMAP=$(append_list "$i" "$FBIDXLIST" "-1")
  #log_debug "server selection: ordered result: '$GLOBAL_STATE_PEER_IDXMAP'"
  :
}

# keep line
