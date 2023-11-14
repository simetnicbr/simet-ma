#shellcheck shell=ash
# Copyright (c) 2023 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# Builds parameters for several measurements from a profile
#
# function subtask_msmtprofile_tcpbw
#  - input var: AGENT_ID, AGENT_TOKEN
#  - input data: msmt_profiles.json, MEDIANRTT (us)
#  - output var: TCPBW_MSMT_PARAMS
#
# Dependencies:
# - jsonfilter (default installed at OpenWRT) as $JSONFILTER
#
# msmt_profiles.json:
#   must be ordered from lowest to highest RTT in the selector.
#
################################################################################

subtask_msmtprofile_tcpbw() {
  TCPBW_MSMT_PARAMS=
  [ -s "$BASEDIR/msmt_profiles.json" ] || return 0

  # for now, we use the RTT from TWAMP and have no other sources
  # of RTT
  [ "$TWAMP_MEDIANRTT" -gt 0 ] 2>/dev/null && {
    MEDIANRTT="$TWAMP_MEDIANRTT"
    log_debug "TCPBW: measurement profile selection will be based on TWAMP median RTT"
  }

  # RTT <= 49ms covers >75% of the non-wifi/non-mobile SIMET MAs in 2023
  local mrtt
  if [ "$MEDIANRTT" -ge 0 ] 2>/dev/null ; then
    mrtt=$(( MEDIANRTT / 1000 )) || mrtt=49
  else
    mrtt=49
  fi

  # NULL selector is the default entry
  local mjson
  mjson=$("$JSONFILTER" -i "$BASEDIR/msmt_profiles.json" -l1 -e "@.profile_tcpbw[@.selector.rtt_ge_ms <= $mrtt]") \
	  || mjson=$("$JSONFILTER" -i "$BASEDIR/msmt_profiles.json" -l1 -e "@.profile_tcpbw[!@.selector]") \
	  || return 0
  [ -n "$mjson" ] || return 0

  log_debug "TCPBW: selected profile $(printf "%s" "$mjson" | tr -s ' \t\n\v\r' ' ')" || :

  local p
  p=$("$JSONFILTER" -s "$mjson" -e "@.streams") && \
    TCPBW_MSMT_PARAMS=$(append_list "$TCPBW_MSMT_PARAMS" -c "$p")
  p=$("$JSONFILTER" -s "$mjson" -e "@.max_duration_s") &&
    TCPBW_MSMT_PARAMS=$(append_list "$TCPBW_MSMT_PARAMS" -l "$p")
  p=$("$JSONFILTER" -s "$mjson" -e "@.sample_period_ms") &&
    TCPBW_MSMT_PARAMS=$(append_list "$TCPBW_MSMT_PARAMS" -s "$p")
  p=$("$JSONFILTER" -s "$mjson" -e "@.stream_pacing_bytespersec") &&
    TCPBW_MSMT_PARAMS=$(append_list "$TCPBW_MSMT_PARAMS" -X "pacing=$p")
  p=$("$JSONFILTER" -s "$mjson" -e "@.stream_start_delay") &&
    TCPBW_MSMT_PARAMS=$(append_list "$TCPBW_MSMT_PARAMS" -X "txdelay=$p")

  return 0
}

# keep line
