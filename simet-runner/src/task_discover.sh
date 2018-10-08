#shellcheck shell=ash
# Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
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
#  - input var: SERVICE_DISCOVERY_ENDPOINT
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

discover_init() {
  GLOBAL_STATE_CURRENT_PEER=-1
  if [ "$MOCK_API_SERVICE_DISCOVERY" = "true" ]; then
    cp "$MOCK_SERVICE_DISCOVERY_RESPONSE" $BASEDIR/services.json
    _debug "Mocking request to API_SERVICE_DISCOVERY with precanned response: $BASEDIR/services.json"
    return    
  fi
  curl -s "$API_SERVICE_DISCOVERY" > $BASEDIR/services.json
}

discover_next_peer() {
  local _peer="undefined"
  GLOBAL_STATE_CURRENT_PEER=$(( $GLOBAL_STATE_CURRENT_PEER + 1 ))
  _debug "Probing for peer at list position: $GLOBAL_STATE_CURRENT_PEER"
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
    TWAMP)
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
