#shellcheck shell=ash
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
#
# Dependencies:
# - sempl (src/vendor/sempl; https://github.com/nextrevision/sempl)
# - curl
# - sub-scripts
################################################################################

_info "Executing $0"

main(){
  local _result="undefined"
  local _configured=0

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
        ;;
      --debug)
        DEBUG="true"
        ;;
    esac
    shift
  done

  _main_setup
  _main_orchestrate
  _main_cleanup
}

_main_orchestrate(){ 
  # 1. task authentication
  AGENT_ID="undefined"
  AGENT_TOKEN="undefined"
  authentication
  _debug "Authentication: AGENT_ID=$AGENT_ID AGENT_TOKEN=$AGENT_TOKEN"

  # 2. task service discovery
  local _discovered="false"
  discover_init
  discover_next_peer
  while [ $? -eq 0 ]; do
    local _endpoint_base="https://$(discover_service AUTHORIZATION HOST):$(discover_service AUTHORIZATION PORT)/$(discover_service AUTHORIZATION PATH)"
    _info "Discovered measurement peer. Authorization attempt at $_endpoint_base"
    # 3. task authorization: try at successive peers, until first success 
    AUTHORIZATION_TOKEN="undefined"
    authorization "$_endpoint_base" "$AGENT_TOKEN"
    if [ $? -eq 0 ]; then
      _discovered="true"
      break
    fi
    discover_next_peer
  done
  if [ "$_discovered" = "true" ]; then
    _info "Peer discovery and authorization success: Selected peer: $_endpoint_base"
  else
    _error "Peer discovery and authorization failure: Last attempt at peer: $_endpoint_base"
    exit 1
  fi

  # 4. task twamp
  _task_twamp "4"
  _task_twamp "6"

  # 5. task bw tcp
  _task_tcpbw "4"
  sleep 3
  _task_tcpbw "6"

  # 6. task report
  _info "Start task REPORT"
  export _report_dir="$BASEDIR/report"
  export _lmap_report_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  _sempl "$TEMPLATE_DIR/report.template" "$_report_dir/result.json"
  local _endpoint="https://$(discover_service REPORT HOST):$(discover_service REPORT PORT)/$(discover_service REPORT PATH)"
  local _report=$( cat "$_report_dir/result.json" )
  _resp=$(curl \
    --request POST \
    --header "Content-Type: application/yang.data+json" \
    --header "Authorization: Bearer $AGENT_TOKEN" \
    --data "$_report"  \
    --silent \
    --fail \
    --location \
    --show-error \
    --verbose \
    "${_endpoint}measure" 2>&1
  ) || {
    _log "POST $_endpoint failed. See the HTTP Trace in the following log lines."
    _log "HTTP Trace: ${_resp}"
    _info "Task REPORT failed"
    return 1
  }
  _info "End task REPORT"
}

_task_twamp(){
  local _af="$1"
  if [[ "$_af" != "4" && "$_af" != "6" ]]; then
    _error "Aborting task TWAMP IPvX. Unknown address familiy '$_af'."
    return 1
  fi
  if [[ "$TWAMPC" = "NO" || "$TWAMPC" = "no" || "$TWAMPC" = "No" ]]; then
    _info "Skipping task TWAMP IPv$_af"
    return 0
  fi
  _info "Start task TWAMP IPv$_af"
  local _host=$( discover_service TWAMP HOST )
  local _port=$( discover_service TWAMP PORT )
  local _about=$( $TWAMPC -V | head -n1)
  set -f && set -- $_about && set +f
  export _task_name="$LMAP_TASK_NAME_PREFIX$1" # " twampc 1.2.3-ABC " => "twampc"
  export _task_version=$2 # " twampc 1.2.3-ABC " => "1.2.3-ABC"
  export _task_dir="$BASEDIR/report/twamp-ipv$_af" 
  export _task_action="packettrain_udp_ipv${_af}_to_nearest_available_peer"
  export _task_parameters='{ "host": "'$_host'", "port": ['$_port'] }'
  export _task_options='[]'
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  _debug "Executing: $TWAMPC -$_af -p $_port $_host > $_task_dir/tables/twamp.json"
  eval "$TWAMPC -$_af -p $_port $_host > $_task_dir/tables/twamp.json"
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  export _task_status="$?"
  if [ "$_task_status" -ne 0 ]; then
    rm -f $_task_dir/tables/*
  fi
  _sempl "$TEMPLATE_DIR/task.template" "$_task_dir/result.json"
  _info "End Task TWAMP IPv$_af"
}

_task_tcpbw(){
  local _af="$1"
  if [[ "$_af" != "4" && "$_af" != "6" ]]; then
    _error "Aborting task TCPBW IPvX. Unknown address familiy '$_af'."
    return 1
  fi
  if [[ "$TCPBWC" = "NO" || "$TCPBWC" = "no" || "$TCPBWC" = "No" ]]; then
    _info "Skipping task TCPBW IPv$_af"
    return 0
  fi
  _info "Start task TCPBW IPv$_af"
  local _host=$( discover_service TCPBW HOST )
  local _port=$( discover_service TCPBW PORT )
  local _path=$( discover_service TCPBW PATH | sed 's/.$//' )
  local _about=$( $TCPBWC -V | head -n1)
  set -f && set -- $_about && set +f
  export _task_name="$LMAP_TASK_NAME_PREFIX$1" # " tcpbw 1.2.3-ABC " => "tcpbw"
  export _task_version=$2 # " tcpbw 1.2.3-ABC " => "1.2.3-ABC"
  export _task_dir="$BASEDIR/report/tcpbw-ipv$_af" 
  export _task_action="bandwidth_tcp_ipv${_af}_to_nearest_available_peer"
  export _task_parameters='{ "host": "'$_host'", "port": ['$_port'] }'
  export _task_options='[]'
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  _debug "Executing: $TCPBWC -$_af -d $AGENT_ID -j $AUTHORIZATION_TOKEN https://${_host}:${_port}/${_path} > $_task_dir/tables/tcpbw.json"
  eval "$TCPBWC -$_af -d $AGENT_ID -j $AUTHORIZATION_TOKEN https://${_host}:${_port}/${_path}  > $_task_dir/tables/tcpbw.json"
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  export _task_status="$?"
  if [ "$_task_status" -ne 0 ]; then
    rm -f $_task_dir/tables/*
  fi
  _sempl "$TEMPLATE_DIR/task.template" "$_task_dir/result.json"
  _info "End Task TCPBW IPv$_af"
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
  local _time_of_exection=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  # 1. pepare dir structure
  BASEDIR="/tmp/simet-ma/$_time_of_exection"
  _debug "Files will be collected in $BASEDIR"
  mkdir -p "$BASEDIR/report"

  # 2. prepare env variables
  export REPORT_SCHEDULE="$LMAP_SCHEDULE"
  export REPORT_EVENT="$_time_of_exection"
  export REPORT_MAC_ADDRESS=$( get_mac_address.sh )
}

_main_cleanup(){
  # delete files of this execution
  if [ "$DEBUG" != "true" ]; then
    rm -fr $BASEDIR
  fi
}

_main_config(){
  . "$1"
  _info "Loaded config '$1': AGENT_ID_FILE=$AGENT_ID_FILE AGENT_TOKEN_FILE=$AGENT_TOKEN_FILE API_SERVICE_DISCOVERY=$API_SERVICE_DISCOVERY AGENT_LOCK=$AGENT_LOCK TEMPLATE_DIR=$TEMPLATE_DIR LMAP_SCHEDULE=$LMAP_SCHEDULE LMAP_TASK_NAME_PREFIX=$LMAP_TASK_NAME_PREFIX TWAMPC=$TWAMPC TCPBWC=$TCPBWC"
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
  if [ "$_msg" != "" ]; then
    _error "Exit due to missing config params: $_msg"
    exit 1
  fi
}

# always execute entry point
main "$@"

# keep line
