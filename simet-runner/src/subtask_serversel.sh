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
#  - output file: services_reorder.json (for ServiceList report metric)
#
# Dependencies:
# - jsonfilter (default installed at OpenWRT) as $JSONFILTER
#
################################################################################

_generate_reordermap_json() {
  local outjson="$BASEDIR/services_reorder.json"
  local map="$*"
  {
    printf '{ "rtt_serversel": [ '
    while [ -n "$map" ] ; do
      local e="${map%% *}"
      map="${map#* }"
      [ -z "$e" ] || [ "$e" -lt 0 ] && break
      printf %s "$e, " || break
    done | sed -e 's/, *$//'
    printf '] }'
  } > "$outjson"
  :
}

_twquick() {
  local tw_tag="$1"
  local tw_host="$2"
  shift 2

  local tw_ip4pid
  local tw_ip6pid
  log_verbose "server selection: peer #$tw_tag: $tw_host, TWAMP light measurement"
  "$TWAMPC" -m light -qq -R summary -O "$BASEDIR/serversel/twlight_result_${tw_tag}_ip4.json" \
      -c "$TWQUICK_PKTCOUNT" \
      -i "$TWQUICK_PKTDELAY" \
      -T "$TWQUICK_PKTTIMEOUT" \
      -p "$TWQUICK_REMOTEPORT" \
      -k "$TWQUICK_KEY" \
      -4 "$tw_host" \
    & tw_ip4pid=$!
  "$TWAMPC" -m light -qq -R summary -O "$BASEDIR/serversel/twlight_result_${tw_tag}_ip6.json" \
      -c "$TWQUICK_PKTCOUNT" \
      -i "$TWQUICK_PKTDELAY" \
      -T "$TWQUICK_PKTTIMEOUT" \
      -p "$TWQUICK_REMOTEPORT" \
      -k "$TWQUICK_KEY" \
      -6 "$tw_host" \
    & tw_ip6pid=$!

  local tw_ip4res=0
  local tw_ip6res=0
  wait "$tw_ip4pid" || {
    tw_ip4res=$?
    rm "$BASEDIR/serversel/twlight_result_${tw_tag}_ip4.json"
  }
  wait "$tw_ip6pid" || {
    tw_ip6res=$?
    rm "$BASEDIR/serversel/twlight_result_${tw_tag}_ip6.json"
  }

  # both failed
  [ $tw_ip4res -ne 0 ] && [ $tw_ip6res -ne 0 ] && return 1

  # both sucessfull, remap 100% packet loss to failure, pick
  # ipv6 over ipv4.
  local i
  for i in ip6 ip4 ; do
    # shellcheck disable=SC2015
    j=$("$JSONFILTER" -i "$BASEDIR/serversel/twlight_result_${tw_tag}_$i.json" \
      -e "PKTSENT=@.results_summary.packets_sent" \
      -e "PKTRCVD=@.results_summary.packets_received_valid" ) && eval "$j" || {
	log_debug "server selection: incorrect or missing data in results for peer #$tw_tag, $i"
	rm -f "$BASEDIR/serversel/twlight_result_${tw_tag}_$i.json"
      }
    # shellcheck disable=SC2015
    [ "$PKTSENT" -eq "$TWQUICK_PKTCOUNT" ] 2>/dev/null && [ "$PKTRCVD" -gt 0 ] 2>/dev/null || continue

    [ -s "$BASEDIR/serversel/twlight_result_${tw_tag}_$i.json" ] && {
      mv "$BASEDIR/serversel/twlight_result_${tw_tag}_$i.json" "$BASEDIR/serversel/twlight_result_${tw_tag}.json"
      return 0
    }
  done

  # invalid results from peer, or both IP families lost too many packets
  return 1
}

_twquick_wait() {
  local _twpid="$1"
  local _peer_id="$2"
  wait "$_twpid" || {
    log_debug "server selection: peer #$_peer_id discarded: twamp client returned status $?"
    return 1
  }
  [ -s "$BASEDIR/serversel/twlight_result_$_peer_id.json" ] || {
    log_debug "server selection: peer #$_peer_id discarded: no/empty result file"
    return 1
  }
  local j
  j=$("$JSONFILTER" -i "$BASEDIR/serversel/twlight_result_$_peer_id.json" \
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
  MEDIANRTT=$("$JSONFILTER" -i "$BASEDIR/serversel/twlight_result_$_peer_id.json" \
      -e "@.results_summary.rtt.rtt_median_us" ) && [ "$MEDIANRTT" -ge 0 ] 2>/dev/null || {
    log_debug "server selection: peer #$_peer_id missing or invalid median RTT, discarded"
    return 1
  }
  [ "$TWQUICK_PRECISION" -gt 1 ] && {
    NMEDIANRTT=$(( ( (MEDIANRTT + (TWQUICK_PRECISION / 2)) / TWQUICK_PRECISION ) * TWQUICK_PRECISION )) 2>/dev/null && {
      log_debug "server selection: peer #$_peer_id: latency $MEDIANRTT rounded to $NMEDIANRTT"
      MEDIANRTT="$NMEDIANRTT"
    }
  }
  :
}

_serversel_getresults() {
  local WPIDLIST="$1"
  local WDATLIST="$2"
  local WIDXLIST="$3"
  local MEDIANRTT
  local i
  #log_debug "waiting for twamp client PIDs $WPIDLIST"

  for i in $WPIDLIST ; do
    WIDX="${WIDXLIST%% *}"
    WDAT="${WDATLIST%% *}"
    WIDXLIST="${WIDXLIST#* }"
    WDATLIST="${WDATLIST#* }"
    if _twquick_wait "$i" "$WIDX" ; then
      log_verbose "server selection: peer #$WIDX: network RTT is approximately $MEDIANRTT microseconds"
      RESIDX=$(append_list "$RESIDX" "$WIDX")
      RESDAT=$(append_list "$RESDAT" "$WDAT")
      RESRTT=$(append_list "$RESRTT" "$MEDIANRTT")
      PCNT=$(( PCNT + 1 ))
    fi
  done
}

subtask_serverselection() {
  local _services="$BASEDIR/services.json"

  [ -s "$_services" ] || return
  [ -s "$BASEDIR/serversel/twampquick_parameters.json" ] || return
  [ -x "$TWAMPC" ] || return

  local j
  j=$("$JSONFILTER" -i "$BASEDIR/serversel/twampquick_parameters.json" \
    -e 'TWQUICK_PAYLOADSIZE=@.twamp_payload_size' \
    -e 'TWQUICK_PKTCOUNT=@.twamp_packet_count' \
    -e 'TWQUICK_PKTDELAY=@.twamp_packet_delay_us' \
    -e 'TWQUICK_PKTTIMEOUT=@.twamp_packet_timeout_us' \
    -e 'TWQUICK_REMOTEPORT=@.reflector_port' \
    -e 'TWQUICK_KEY=@.auth_key_base64') || return
  eval "$j" || return
  TWQUICK_DROPLIMIT=$("$JSONFILTER" -i "$BASEDIR/serversel/twampquick_parameters.json" \
    -e '@.twamp_packet_drop_limit') || TWQUICK_DROPLIMIT=1
  TWQUICK_PRECISION=$("$JSONFILTER" -i "$BASEDIR/serversel/twampquick_parameters.json" \
    -e '@.twamp_desired_precision_us') || TWQUICK_PRECISION=0

  log_info "server selection: measuring network roundtrip time to the available servers..."
  log_debug "server selection: latency-based: send and receive $TWQUICK_PKTCOUNT packets in $TWQUICK_PKTTIMEOUT microseconds"
  [ "$TWQUICK_PRECISION" -gt 1 ] 2>/dev/null && \
    log_verbose "server selection: RTT will be rounded to a precision of $TWQUICK_PRECISION microseconds"

  [ "$GLOBAL_SERIALIZE_SERVERSEL" -eq 1 ] 2>/dev/null && \
    log_info "server selection: limiting memory usage during selection, this will be slow!"

  local SCNT=0
  local S_PUBPEER
  local S_HOST
  local S_LEVEL

  local PEERPIDLIST=
  local PEERIDXLIST=
  local PEERDATLIST=
  local FBIDXLIST=
  local RESIDX=
  local RESRTT=
  local RESDAT=
  local PCNT=0

  while "$JSONFILTER" -i "$_services" -t "@[$SCNT]" >/dev/null 2>&1 ; do
    j=$("$JSONFILTER" -i "$_services" \
	    -e "S_PUBPEER=@[$SCNT].isPublicPeer" \
	    -e "S_LEVEL=@[$SCNT].localityListIndex" \
	    -e "S_HOST=@[$SCNT].twamp[0].hostname" )\
      || j=
    [ -n "$j" ] && {
      eval "$j" || return
      if [ "$S_PUBPEER" -eq 0 ] && [ -n "$S_HOST" ] ; then
	_twquick "$SCNT" "$S_HOST" 2>/dev/null & TWLPID=$!
	PEERPIDLIST=$(append_list "$PEERPIDLIST" "$TWLPID")
	PEERDATLIST=$(append_list "$PEERDATLIST" "$S_LEVEL")
	PEERIDXLIST=$(append_list "$PEERIDXLIST" "$SCNT")

	# sync wait on low-memory hosts
	[ "$GLOBAL_SERIALIZE_SERVERSEL" -eq 1 ] 2>/dev/null && {
	  # Updates RESIDX, RESRTT, PCNT
	  _serversel_getresults "$PEERPIDLIST" "$PEERDATLIST" "$PEERIDXLIST"
	  PEERPIDLIST=
	  PEERIDXLIST=
	  PEERDATLIST=
	}
      elif [ -n "$S_HOST" ] ;  then
	log_verbose "server selection: peer #$SCNT: $S_HOST, global last-choice peer"
	FBIDXLIST=$(append_list "$FBIDXLIST" "$SCNT")
      fi
    }
    SCNT=$(( SCNT + 1 ))
  done

  # Updates RESIDX, RESRTT, PCNT
  _serversel_getresults "$PEERPIDLIST" "$PEERDATLIST" "$PEERIDXLIST"

  [ -z "$RESIDX" ] || [ -z "$RESDAT" ] || [ -z "$RESRTT" ] || [ "$PCNT" -eq 0 ] && {
    log_info "server selection: latency-based selection failed, using alternative selection method"
    return
  }

  # order by (service-list tier, rtt, service-list array index)
  #log_debug "server selection: before sort: PCNT=$PCNT RESRTT='$RESRTT' RESIDX='$RESIDX' RESDAT='$RESDAT'"
  local i
  i=$(while [ "$PCNT" -gt 0 ] ; do
	# busybox "small" sort (no -k, -t) workaround: zero-pad all fields before sort
	printf "%020d:%020d:%010d\n" "${RESDAT%% *}" "${RESRTT%% *}" "${RESIDX%% *}"
	RESRTT="${RESRTT#* }"
	RESIDX="${RESIDX#* }"
	RESDAT="${RESDAT#* }"
	PCNT=$(( PCNT - 1 ))
      done \
      | LC_ALL=C sort \
      | cut -d ':' -f 3 | tr -s '\n\r' ' ' \
      | sed -e 's/^[ \t\n]*//' -e 's/[ \t\n]*$//') || {
    log_debug "server selection: failed to sort by latency."
    return
  }
  # we need to remove zero-padding to avoid parsing it as octal
  GLOBAL_STATE_PEER_IDXMAP=$(append_list "$i" "$FBIDXLIST" "-1" | \
    sed -e 's/^0\+\([0-9]\)/\1/' -e 's/ 0\+\([0-9]\)/ \1/g')
  #log_debug "server selection: ordered result: '$GLOBAL_STATE_PEER_IDXMAP'"
  _generate_reordermap_json "$GLOBAL_STATE_PEER_IDXMAP"
  :
}

# keep line
