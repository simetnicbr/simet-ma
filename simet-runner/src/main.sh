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
# ./dist/simet_agent_unix.sh --config ./dist/simet_agent_unix.conf --debug
#
# Dependencies:
# - sempl (src/vendor/sempl; https://github.com/nextrevision/sempl)
# - curl
# - sub-scripts
################################################################################

_info "Executing $0"

main(){
  local _config="undefined"
  local _result="undefined"

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --config)
        _config="$2"
        ;;
      --debug)
        DEBUG="true"
        ;;
    esac
    shift
  done

  _main_config "$_config"
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
  while [ discover_next_peer ]; do
    local _endpoint_base="https://$(discover_service AUTHORIZATION HOST):$(discover_service AUTHORIZATION PORT)/$(discover_service AUTHORIZATION PATH)"
    _info "Discovered measurement peer. Authorization attempt at $_host"
    # 3. task authorization: try at successive peers, until first success 
    AUTHORIZATION_TOKEN="undefined"
    authorization "$_endpoint_base" "$AGENT_TOKEN"
    if [ $? -eq 0 ]; then
      _discovered="true"
      break
    fi
  done
  if [ "$_discovered" = "true" ]; then
    _info "Peer discovery and authorization success: Selected peer: $_host"
  else
    _error "Peer discovery and authorization failure: Last attempt at peer: $_host"
    exit 1
  fi

  # 4. task twamp
  _task_twamp "4"
  _task_twamp "6"

  # [TODO sprint 2] 5. task geolocation 
  # _info "Start task GEOLOCATION"
  # export _task_dir="$BASEDIR/report/geolocation" 
  # export _lmap_task_name="undefined"
  # export _lmap_task_version="undefined"
  # mkdir -p "$_task_dir/tables"
  # _sempl "$TEMPLATE_DIR/task.template" "$_task_dir/result.json"
  # _info "End task GEOLOCATION"

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
    "$_endpoint/measure" 2>&1
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
  local _about=$( $TWAMPC -V )
  export _task_dir="$BASEDIR/report/twamp-ipv$_af" 
  export _lmap_task_name=$( echo "$_about" | head -n1 | sed -En 's/^\s*(\S+)\s+(\S+)\s*/\1/p' )    # " twampc 1.2.3-ABC " => "twampc"
  export _lmap_task_version=$( echo "$_about" | head -n1 | sed -En 's/^\s*(\S+)\s+(\S+)\s*/\2/p' ) # " twampc 1.2.3-ABC " => "1.2.3-ABC"
  mkdir -p "$_task_dir/tables"
  _debug "Executing: $TWAMPC -$_af -p $_port $_host > $_task_dir/tables/twamp.json"
  eval "$TWAMPC -$_af -p $_port $_host > $_task_dir/tables/twamp.json"
  export _lmap_task_status="$?"
  if [ "$_lmap_task_status" -ne 0 ]; then
    export _lmap_task_status 
    rm -f $_task_dir/tables/*
  fi
  _sempl "$TEMPLATE_DIR/task.template" "$_task_dir/result.json"
  _info "End Task TWAMP IPv$_af"
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
#   LMAP_TASK_SCHEDULE
#   LMAP_TASK_ACTION
#   LMAP_TASK_EVENT
#   LMAP_TASK_START
################################################################################
_main_setup(){
  # 1. pepare dir structure
  BASEDIR=/tmp/simet-ma/$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  _debug "Files will be collected in $BASEDIR"
  mkdir -p "$BASEDIR/report"

  # 2. prepare env variables
  export LMAP_TASK_SCHEDULE="simet_base_schedule"
  export LMAP_TASK_ACTION="simet_base_action"
  export LMAP_TASK_EVENT="simet_base_event"
  export LMAP_TASK_START="simet_base_start"
}

_main_cleanup(){
  # delete files of this execution
  if [ "$DEBUG" != "true" ]; then
    rm -fr $BASEDIR
  fi
}

_main_config(){
  source "$1"
  _debug "Loaded config '$1': AGENT_ID_FILE=$AGENT_ID_FILE AGENT_TOKEN_FILE=$AGENT_TOKEN_FILE API_SERVICE_DISCOVERY=$API_SERVICE_DISCOVERY AGENT_LOCK=$AGENT_LOCK TEMPLATE_DIR=$TEMPLATE_DIR TWAMPC=$TWAMPC"
  local _msg=""
  if [ "$AGENT_ID_FILE" = "" ]; then _msg="$_msg AGENT_ID_FILE"; fi
  if [ "$AGENT_TOKEN_FILE" = "" ]; then _msg="$_msg AGENT_TOKEN_FILE"; fi
  if [ "$API_SERVICE_DISCOVERY" = "" ]; then _msg="$_msg API_SERVICE_DISCOVERY"; fi
  if [ "$AGENT_LOCK" = "" ]; then _msg="$_msg AGENT_LOCK"; fi
  if [ "$TEMPLATE_DIR" = "" ]; then _msg="$_msg TEMPLATE_DIR"; fi
  if [ "$TWAMPC" = "" ]; then _msg="$_msg TWAMPC"; fi
  if [ "$_msg" != "" ]; then
    _error "Exit due to missing config params: $_msg"
    exit 1
  fi
}

# always execute entry point
main "$@"

# keep line
