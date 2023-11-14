#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# Discover endpoints for measurements.
#   - 1. discover a measurement peer
#   - 2. discover a service endpoint (host, port, path) at the selected measurement peer
#
#
# Stateful iterator API
#
# Execution:
# 
# discover_init
# while [ $( discover_next_peer ) -eq 0 ]; do
#   host=$( discover_service AUTHORIZATION HOST )
#   port=$( discover_service AUTHORIZATION PORT )
#   path=$( discover_service AUTHORIZATION PATH )
#   
#   # try the target operation at successive peers, until first success
#   result=$( target_operation host port path )
#   if [ result -eq 0 ]; then
#     break
#   fi
# done
#
# function discover_init() 
#  - input var: SERVICE_DISCOVERY_ENDPOINT, AGENT_ID, AGENT_TOKEN
#
# function discover_next_peer()
#  - out status 0, if next peer exists
#  - out status 1, if next peer does NOT exist
#
# function discover_service() 
#  - in params: service element
#  - out text: value
#  - example: 
#     discover_service AUTHORIZATION HOST
#     api.simet.nic.br
#
# Dependencies:
# - curl
# - jsonfilter (default installed at OpenWRT) as $JSONFILTER
#
################################################################################

report_servicelist_output() {
  export _task_name="${LMAP_TASK_NAME_PREFIX}servicelist-output"
  export _task_version="$PACKAGE_VERSION"
  export _task_dir="$BASEDIR/report/0metadata-servicelist"
  export _task_action="report_servicelist"
  export _task_parameters='{ }'
  export _task_options='[]'
  export _task_extra_tags='"simet.nic.br_subsystem-id:simet2_std-v1",'
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  export _task_status="0"
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  task_json_template "urn:ietf:metrics:perf:Priv_SPMonitor_Passive_ServiceList-output__Multiple_Raw" \
      "$BASEDIR/services.json" "services_json" \
      "$BASEDIR/services_reorder.json" "reordering_map" \
    > "$_task_dir/result.json" || :
}

discover_init() {
  GLOBAL_STATE_CURRENT_PEER=-1
  # GLOBAL_STATE_PEER_IDXMAP should be either empty, or space-separated list of indexes
  # a negative value or invalid number must signal the end of the IDXMAP
  GLOBAL_STATE_PEER_IDXMAP=
  if [ -n "$SIMET_SERVICELIST_OVERRIDE" ] ; then
    cp "$SIMET_SERVICELIST_OVERRIDE" "$BASEDIR/services.json" || {
      log_error "Failed when trying to override services.json from --services command line option"
      exit 1
    }
    log_debug "Overriding services.json by command line request"
    return    
  fi

  # Do we have the memory budget to run many twampc in parallel ?
  [ -z "$GLOBAL_SERIALIZE_SERVERSEL" ] && {
    GLOBAL_SERIALIZE_SERVERSEL=$(awk \
      'BEGIN                 { NOTENOUGH=0 ; MAV=0 } ;
       /^MemAvailable:.*kB$/ { MAV=$2 } ;
       END                   { if (MAV < 25000) NOTENOUGH=1 ; print NOTENOUGH }' \
      /proc/meminfo) \
    || GLOBAL_SERIALIZE_SERVERSEL=0
  }

  mkdir -p "$BASEDIR/serversel"

  local _curl1_pid
  curl \
    --request GET \
    --header "Authorization: Bearer $AGENT_TOKEN" \
    --silent \
    --fail \
    --location \
    --connect-timeout 10 \
    --max-time 15 \
    --url "$API_SERVICE_DISCOVERY" > "$BASEDIR/services.json" \
  & _curl1_pid=$!

  local _curl2_pid
  local _curl2_endpoint="$API_SERVER_SELECTION/v1/request_quick"
  curl \
    --request GET \
    --header "Authorization: Bearer $AGENT_TOKEN" \
    --silent \
    --fail \
    --location \
    --connect-timeout 10 \
    --max-time 15 \
    --url "$_curl2_endpoint/$AGENT_ID" > "$BASEDIR/serversel/twampquick_parameters.json" \
  & _curl2_pid=$!

  wait $_curl1_pid
  wait $_curl2_pid && log_debug "Latency-based server selection parameters received"
}

discover_next_peer() {
  local _peer="undefined"
  if [ -n "$GLOBAL_STATE_PEER_IDXMAP" ] ; then
    log_debug "current server-selection map: $GLOBAL_STATE_PEER_IDXMAP"
    GLOBAL_STATE_CURRENT_PEER="${GLOBAL_STATE_PEER_IDXMAP%% *}"
    GLOBAL_STATE_PEER_IDXMAP="${GLOBAL_STATE_PEER_IDXMAP#* }"
    # end of list? negative or empty, note that empty is not supposed to be possible
    [ -n "$GLOBAL_STATE_CURRENT_PEER" ] && [ "$GLOBAL_STATE_CURRENT_PEER" -ge 0 ] \
      || return 1
  else
    GLOBAL_STATE_CURRENT_PEER=$(( GLOBAL_STATE_CURRENT_PEER + 1 ))
  fi
  log_debug "Probing for peer at list position: $GLOBAL_STATE_CURRENT_PEER"
  _peer=$($JSONFILTER -i "$BASEDIR/services.json" -t "@[$GLOBAL_STATE_CURRENT_PEER]")
  if [ "$_peer" != "" ]; then
    return 0
  else
    return 1
  fi
}

discover_service() {
  local _service="undefined"
  local _element="undefined"

  case "$1" in
    AUTHORIZATION)
      _service="serverMonitor"
    ;;
    REPORT)
      _service="collector"
    ;;
    TWAMP|TRACEROUTE)
      _service="twamp"
    ;;
    TCPBW)
      _service="tcpbw"
    ;;
  esac

  case "$2" in
    HOST)
      _element="hostname"
    ;;
    PORT)
      _element="ports[0]"
    ;;
    PATH)
      _element="basePath"
    ;;
  esac

  _discover_service $_service $_element
}

_discover_service(){
  local _service="undefined"
  local _element="undefined"
  
  _service="$1"
  _element="$2"
  _extracted=$($JSONFILTER -i "$BASEDIR/services.json" -e "@[$GLOBAL_STATE_CURRENT_PEER].$_service[0].$_element")
  echo "$_extracted"
}

# keep line
