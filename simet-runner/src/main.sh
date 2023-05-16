#shellcheck shell=ash
# SIMET2 MA task runner - main program (shell version)
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
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

################################################################################
# Tasks
# - Verificação do AgentToken
# - ServerList
# - MeasureToken
# - TWAMP
# - Geolocation
# - Report LMAP
#
# Execution (after build):
# ./dist/simet-ma_run.sh --config ./dist/simet_agent_unix.conf --debug
# [--test TWAMP|TWAMPFAST|TCPBW|GEOLOC] [--peer-reachability]
#
# Dependencies:
# - curl
# - sub-scripts
# - flock
################################################################################

_main_locked(){
  log_important "$PACKAGE_STRING starting..."

  rc=0
  _main_setup && _main_orchestrate || rc=$?
  _main_cleanup

  log_debug "$PACKAGE_STRING end, status=$rc"
  return $rc
}

main(){
  local _result="undefined"
  local _configured=0

  SETLOCK="true"
  ALLPEERS=0
  MEASUREMENT_CONTEXT=

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --config)
        if [ $_configured -eq 0 ] ; then
          _main_config "$2" || exit 1
          _configured=1
        else
          [ -r "$2" ] && _main_config "$2"
        fi
        shift
        ;;
      --debug)
        DEBUG="true"
        VERBOSE="true"
        ;;
      --test)
        [ -n "$MEASUREMENT_CONTEXT" ] && {
          log_error "--test cannot be used with specific measurement contexts"
          exit 1
        }
        if [ -n "$2" ] ; then
          RUN_ONLY_TASK="$2"
        else
          log_error "--test requires a test name as a parameter: TWAMP, TWAMPFAST, TCPBW, GEOLOC"
          exit 1
        fi
        shift
        ;;
      --peer-reachability)
        ALLPEERS=1
        RUN_ONLY_TASK="TWAMPFAST"
        MEASUREMENT_CONTEXT="every-mp-from-servicelist"
        ;;
      -v|--verbose)
        VERBOSE="true"
        QUIET="false"
        ;;
      -q|--quiet)
        VERBOSE="false"
        QUIET="true"
        ;;
      --syslog)
        LOG_TO_SYSLOG=true
        ;;
      --no-lock)
        SETLOCK="false"
        ;;
      --lock)
        SETLOCK="true"
        ;;
    esac
    shift
  done

  if [ $_configured -eq 0 ] ; then
    for i in $SIMET_CONFIG_FILES ; do
      [ -r "$i" ] && _main_config "$i"
    done
  fi

  if [ $SETLOCK != "true" ] || [ -z "$AGENT_LOCK" ] ; then
    _main_locked || return $?
    return 0
  fi

  [ -r "$AGENT_LOCK" ] || touch "$AGENT_LOCK" || {
    log_error "cannot create $AGENT_LOCK"
    exit 1
  }
  (
    for i in 1 2 3 4 5 ; do
      flock -n -x 9 && {
        _main_locked || exit $?
        exit 0
      }
      sleep 1
    done
    log_error "Measurement lock is already taken, exiting..."
    exit 1
  ) </dev/null 9< "$AGENT_LOCK" || return $?
  :
}

# test number can be empty, or 1.. when testing multiple peers in the same run
_main_run(){
  local _tstid_prefix=
  [ -n "$1" ] && {
    _tstid_prefix=$(printf '%03d-' "$1") || {
      log_error "internal error: illegal test number: $1"
      exit 1
    }
  }

  log_notice "measurement peer: $_auth_endpoint"
  [ -n "$_tstid_prefix" ] && log_debug "measurement prefix for report: $_tstid_prefix"

  ## if RUN_ONLY_TASK is set, we only run that one
  # 4. task twamp + traceroute
  if [ -z "$RUN_ONLY_TASK" ] || [ "$RUN_ONLY_TASK" = "TWAMP" ] ; then
    _task_twamp "4" "$_tstid_prefix"
    _task_traceroute "4" "$_tstid_prefix"
    _task_twamp "6" "$_tstid_prefix"
    _task_traceroute "6" "$_tstid_prefix"
  elif [ "$RUN_ONLY_TASK" = "TWAMPFAST" ] ; then
    _task_twamp "4" "$_tstid_prefix" $TWAMPFAST_OPT
    _task_traceroute "4" "$_tstid_prefix" &
    _task_twamp "6" "$_tstid_prefix" $TWAMPFAST_OPT
    _task_traceroute "6" "$_tstid_prefix" &
  fi

  # 5. task bw tcp
  if [ -z "$RUN_ONLY_TASK" ] || [ "$RUN_ONLY_TASK" = "TCPBW" ] ; then
    _task_tcpbw "4" "$_tstid_prefix"
    sleep 3
    log_debug "Refresh the authorization token for ipv6."
    authorization "$_auth_endpoint" "$AGENT_TOKEN"
    if [ $? -eq 0 ]; then
      _task_tcpbw "6" "$_tstid_prefix"
    else
      log_warn "skipping ipv6 throughput measurement: authorization has been denied"
    fi
  fi
}

_main_orchestrate(){ 
  # 1. task authentication
  AGENT_ID="undefined"
  AGENT_TOKEN="undefined"
  authentication
  log_debug "Authentication: AGENT_ID=$AGENT_ID"

  # 2. task service discovery
  local _discovered="false"
  local _loopcounter=1
  local _collector_endpoint=

  discover_init && subtask_serverselection
  discover_next_peer
  while [ $? -eq 0 ]; do
    local _auth_endpoint="https://$(discover_service AUTHORIZATION HOST):$(discover_service AUTHORIZATION PORT)/$(discover_service AUTHORIZATION PATH)"
    log_debug "authorization attempt at $_auth_endpoint"
    # 3. task authorization: try at successive peers, until first success 
    AUTHORIZATION_TOKEN=
    authorization "$_auth_endpoint" "$AGENT_TOKEN"
    if [ $? -eq 0 ]; then
      _discovered="true"

      # per-peer test run
      if [ $ALLPEERS -eq 0 ] ; then
        _main_run
        break
      fi

      # this may end up running a measurement in background
      _main_run $_loopcounter && \
         [ -z "$_collector_endpoint" ] && \
	   _collector_endpoint="https://$(discover_service REPORT HOST):$(discover_service REPORT PORT)/$(discover_service REPORT PATH)"
      _loopcounter=$((_loopcounter + 1))
    fi
    discover_next_peer
  done
  if [ "$_discovered" != "true" ]; then
    log_error "Peer discovery and authorization failed"
    exit 1
  fi

  # once-per-run measurements

  # 6. task geolocation
  if [ -z "$RUN_ONLY_TASK" ] || [ "$RUN_ONLY_TASK" = "GEOLOC" ] ; then
    _task_geolocation
  fi

  _task_environment

  log_info "Waiting for background measurements to complete"
  wait

  # 7. task report
  log_debug "Start task REPORT"
  export _report_dir="$BASEDIR/report"
  export _lmap_report_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  report_template > "$_report_dir/result.json"
  if [ -n "$_collector_endpoint" ] ; then
    local _endpoint="$_collector_endpoint"
  else
    local _endpoint="https://$(discover_service REPORT HOST):$(discover_service REPORT PORT)/$(discover_service REPORT PATH)"
  fi
  if [ -x "$LMAPSENDREPORT" ] ; then
    $LMAPSENDREPORT --fast --use-report "$_report_dir/result.json" "${_endpoint}measure" || {
      log_debug "Task REPORT failed"
      return 1
    }
  else
    log_info "LMAPSENDREPORT config missing, trying a direct submission"
    _resp=$(curl \
      --request POST \
      --header "Content-Type: application/yang.data+json" \
      --header "Authorization: Bearer $AGENT_TOKEN" \
      --data "@$_report_dir/result.json"  \
      --silent \
      --fail \
      --location \
      --show-error \
      --verbose \
      "${_endpoint}measure" 2>&1
    ) || {
      log_error "failed to submit LMAP report, measurement results will be lost"
      log_debug "HTTP Trace: ${_resp}"
      log_debug "Task REPORT failed"
      return 1
    }
    log_notice "LMAP measurement report accepted by collector: $_endpoint"
  fi
  log_debug "End task REPORT"
}

haspipefail(){
  set -o | grep -cq pipefail && return 0
  return 1
}

_task_environment(){
  log_debug "Start task agent environment"
  export _task_name="${LMAP_TASK_NAME_PREFIX}agent-info"
  export _task_version="$PACKAGE_VERSION"
  export _task_dir="$BASEDIR/report/0metadata"
  export _task_action="report_context"
  export _task_parameters='{ }'
  export _task_options='[]'
  export _task_extra_tags='"simet.nic.br_subsystem-id:simet2_std-v1",'
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  ma_environment > "$_task_dir/tables/environment_short.json"
  export _task_status="$?"
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "$_task_status" -ne 0 ]; then
    log_info "agent-info metric failed."
    # we only fail if wriring the metric to $_task_dir failed,
    # do not even bother trying to recover from *that*...
    rm -rf "$_task_dir"
  else
    task_template > "$_task_dir/result.json"
  fi
  log_debug "End task agent environment"
}

_task_geolocation(){
  log_debug "Start task geolocation"
  export _task_name="${LMAP_TASK_NAME_PREFIX}geolocation"
  export _task_version="$PACKAGE_VERSION"
  export _task_dir="$BASEDIR/report/geolocation"
  export _task_action="geolocation_https_bssids"
  export _task_extra_tags=
  export _task_parameters='{ }'
  export _task_options='[]'
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  geolocate > "$_task_dir/tables/geolocation.json"
  export _task_status="$?"
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "$_task_status" -ne 0 ]; then
    log_info "Geolocation attempt failed."
    rm -rf "$_task_dir"
  else
    task_template > "$_task_dir/result.json"
  fi
  log_debug "End task geolocation"
}

_task_twamp(){
  local _af="$1"
  local _tst_prefix="$2"
  shift 2
  local _twamp_opts="$*"
  if [[ "$_af" != "4" && "$_af" != "6" ]]; then
    log_error "Aborting task TWAMP IPvX. Unknown address familiy '$_af'."
    return 1
  fi
  if [[ "$TWAMPC" = "NO" || "$TWAMPC" = "no" || "$TWAMPC" = "No" ]]; then
    log_info "Skipping task TWAMP IPv$_af"
    return 0
  fi
  log_measurement "TWAMP ${_tst_prefix}IPv$_af"
  local _host="ipv$_af.$( discover_service TWAMP HOST )"
  local _port=$( discover_service TWAMP PORT )
  local _about=$( $TWAMPC -V | head -n1)
  set -f && set -- $_about && set +f
  export _task_name="${LMAP_TASK_NAME_PREFIX}twamp" # " twampc 1.2.3-ABC " => "twampc"
  export _task_version=$2 # " twampc 1.2.3-ABC " => "1.2.3-ABC"
  export _task_dir="$BASEDIR/report/twamp-${_tst_prefix}ipv$_af"
  export _task_action="packettrain-udp_to-simet-measurement-peer_${_tst_prefix}ip$_af"
  export _task_parameters='{ "host": "'$_host'", "port": ['$_port'] }'
  export _task_options='[]'
  export _task_extra_tags="\"simet.nic.br_peer-name:$_host\","
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  if haspipefail && [ "$VERBOSE" = "true" ] ; then
    set -o pipefail
    eval "$TWAMPC $_twamp_opts -$_af -p $_port $_host 3>&2 2>&1 1>&3 3<&- >\"$_task_dir/tables/twamp.json\"" | tee "$_task_dir/tables/stderr.txt"
    export _task_status="$?"
    set +o pipefail
  else
    eval "$TWAMPC $_twamp_opts -$_af -p $_port $_host >\"$_task_dir/tables/twamp.json\"" 2>"$_task_dir/tables/stderr.txt"
    export _task_status="$?"
  fi
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "$_task_status" -ne 0 ]; then
    log_error "Task TWAMP IPv$_af, failed with exit code: $_task_status"
    [ -s "$_task_dir/tables/stderr.txt" ] && \
      error_template < "$_task_dir/tables/stderr.txt" > "$_task_dir/tables/stderr.json" && \
      rm -f "$_task_dir/tables/stderr.txt"
#   rm -f "$_task_dir/tables/twamp.json"
  else
    rm -f "$_task_dir/tables/stderr.txt"
  fi
  task_template > "$_task_dir/result.json"
  log_debug "End Task TWAMP ${_tst_prefix}IPv$_af"
}

_task_tcpbw(){
  local _af="$1"
  local _tst_prefix="$2"
  if [[ "$_af" != "4" && "$_af" != "6" ]]; then
    log_error "Aborting task TCPBW IPvX. Unknown address familiy '$_af'."
    return 1
  fi
  if [[ "$TCPBWC" = "NO" || "$TCPBWC" = "no" || "$TCPBWC" = "No" ]]; then
    log_info "Skipping task TCPBW IPv$_af"
    return 0
  fi

  local _tcpbwv=
  if [[ "$DEBUG" = "true" ]] ; then
	  _tcpbwv="-v -v"
  fi

  log_measurement "TCPBW ${_tst_prefix}IPv$_af"
  local _host="ipv$_af.$( discover_service TCPBW HOST )"
  local _port=$( discover_service TCPBW PORT )
  local _path=$( discover_service TCPBW PATH | sed 's/.$//' )
  local _about=$( $TCPBWC -V | head -n1)
  set -f && set -- $_about && set +f
  export _task_name="${LMAP_TASK_NAME_PREFIX}tcp-bandwidth" # " tcpbw 1.2.3-ABC " => "tcpbw"
  export _task_version=$2 # " tcpbw 1.2.3-ABC " => "1.2.3-ABC"
  export _task_dir="$BASEDIR/report/tcpbw-${_tst_prefix}ipv$_af"
  export _task_action="bandwidth-tcp_to-simet-measurement-peer_${_tst_prefix}ip$_af"
  export _task_parameters='{ "host": "'$_host'", "port": ['$_port'] }'
  export _task_options='[]'
  export _task_extra_tags="\"simet.nic.br_peer-name:$_host\","
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  if [ -n "$AUTHORIZATION_TOKEN" ] ; then
    tcpbwauth="-j $AUTHORIZATION_TOKEN"
  else
    tcpbwauth=
  fi
  if haspipefail && [ "$VERBOSE" = "true" ] ; then
    set -o pipefail
    eval "$TCPBWC $_tcpbwv -$_af -d $AGENT_ID $tcpbwauth https://${_host}:${_port}/${_path} 3>&2 2>&1 1>&3 3<&- >\"$_task_dir/tables/tcpbw.json\"" | tee "$_task_dir/tables/stderr.txt"
    export _task_status="$?"
    set +o pipefail
  else
    eval "$TCPBWC $_tcpbwv -$_af -d $AGENT_ID $tcpbwauth https://${_host}:${_port}/${_path} >\"$_task_dir/tables/tcpbw.json\"" 2>"$_task_dir/tables/stderr.txt"
    export _task_status="$?"
  fi
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "$_task_status" -ne 0 ]; then
    log_error "Task TCPBW IPv$_af, failed with exit code: $_task_status"
    [ -s "$_task_dir/tables/stderr.txt" ] && \
      error_template < "$_task_dir/tables/stderr.txt" > "$_task_dir/tables/stderr.json" && \
      rm -f "$_task_dir/tables/stderr.txt"
#   rm -f "$_task_dir/tables/tcpbw.json"
  else
    rm -f "$_task_dir/tables/stderr.txt"
  fi
  task_template > "$_task_dir/result.json"
  log_debug "End Task TCPBW ${_tst_prefix}IPv$_af"
}



################################################################################
# function _main_setup
#   - prepare directory structure to cache task results
#   - prepare environment variables to render the LAMP report
#
#
# Directory structure:
#   $BASEDIR/report/twamp/tables/twamp-ipv4.json
#   $BASEDIR/report/twamp/tables/twamp-ipv6.json
#   $BASEDIR/report/twamp/result.json
#   $BASEDIR/report/report.json
#   $BASEDIR/services.json
#   $BASEDIR/other_files..
#
# Variables
#   REPORT_SCHEDULE
#   REPORT_ACTION
#   REPORT_EVENT
################################################################################
_main_setup(){
  # 1. pepare dir structure
  BASEDIR=$(mktemp -t -d simet-ma-run_XXXXXXXXXXXX) || {
    log_error "could not create temporary work directory"
    exit 1
  }
  log_debug "Files will be collected in $BASEDIR"
  mkdir -p "$BASEDIR/report"

  # Remove $BASEDIR if interrupted to avoid wasting tmpfs space on embedded devices
  trap '_main_run_trap' INT TERM QUIT
  trap 'erc=$? ; _main_cleanup || : ; return $erc' EXIT

  # 2. prepare env variables
  local _time_of_exection=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  export REPORT_SCHEDULE="$LMAP_SCHEDULE"
  export REPORT_EVENT="$_time_of_exection"
  REPORT_MAC_ADDRESS_TAG_ENTRY=
  _macaddress=$( get_mac_address.sh 2>/dev/null | tr -d -c "0-9a-fA-F" )
  if [ -n "$_macaddress" ] ; then
     REPORT_MAC_ADDRESS_TAG_ENTRY=", \"macaddress:${_macaddress}\""
  fi
  export REPORT_MAC_ADDRESS_TAG_ENTRY
}

_main_cleanup(){
  trap - EXIT
  # delete files of this execution
  [ "$DEBUG" != "true" ] && [ -n "$BASEDIR" ] && [ -d "$BASEDIR" ] && rm -fr "$BASEDIR"
  :
}

_main_run_trap(){
  _main_cleanup || :
  log_error "$0: received stop/interrupt signal..."
  exit 143
}

_main_config(){
  . "$1" || {
    log_error "Failed to load config file: $1"
    exit 1
  }
  log_debug "Loaded config file: $1"
  local _msg=""
  if [ "$AGENT_ID_FILE" = "" ]; then _msg="$_msg AGENT_ID_FILE"; fi
  if [ "$AGENT_TOKEN_FILE" = "" ]; then _msg="$_msg AGENT_TOKEN_FILE"; fi
  if [ "$API_SERVICE_DISCOVERY" = "" ]; then _msg="$_msg API_SERVICE_DISCOVERY"; fi
  if [ "$AGENT_LOCK" = "" ]; then _msg="$_msg AGENT_LOCK"; fi
  if [ "$TEMPLATE_DIR" = "" ]; then _msg="$_msg TEMPLATE_DIR"; fi
  if [ "$LMAP_SCHEDULE" = "" ]; then _msg="$_msg LMAP_SCHEDULE"; fi
  if [ "$LMAP_TASK_NAME_PREFIX" = "" ]; then _msg="$_msg LMAP_TASK_NAME_PREFIX"; fi
  if [ "$TWAMPC" = "" ]; then _msg="$_msg TWAMPC"; fi
  if [ "$TCPBWC" = "" ]; then _msg="$_msg TCPBWC"; fi
  if [ "$JSONFILTER" = "" ]; then _msg="$_msg JSONFILTER"; fi
  if [ "$_msg" != "" ]; then
    log_error "Exit due to missing config params: $_msg"
    exit 1
  fi
}

# always execute entry point
main "$@"

# keep line
