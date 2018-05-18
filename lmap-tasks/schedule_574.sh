#!/bin/bash
#
# Execution:
# ./schedule_574.sh --config ./schedule_574.conf
#
# Dependencies:
# - curl
# - jq
# - logger
#

schedule(){
  local _config="undefined"
  local _result="undefined"
  local _dir="undefined"

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --config)
        _config=$2
        ;;
    esac
    shift
  done

  # main steps
  _schedule_setup
  _schedule_orchestrate
  _schedule_cleanup
}

_schedule_orchestrate(){ 
  # service discovery
  discovery --endpoint "$DISCOVERY_ENDPOINT"
  if [[ $? -ne 0 ]]; then
    _log "Discovery failed. Skipping tasks: auth, twamp, tcp and report."
    return 1
  fi

  # authentication token
  _token=$(auth  --agent "$AGENT" --endpoint "$AUTH_ENDPOINT")
  if [[ $? -ne 0 ]]; then
    _log "Auth failed. Skipping tasks: twamp, tcp and report."
    return 1
  fi

  # twamp metric
  $TWAMPC $TWAMP_SERVER > $_dir/twamp.json

  # tcp metric
  $TCPC > $_dir/tcp.json

  # lmap reporting
  report \
    --template "$REPORT_TEMPLATE" \
    --agent "$AGENT" \
    --tabledir "$_dir" \
    --endpoint "$REPORT_ENDPOINT" \
    --jwt "$_token"
  if [[ $? -ne 0 ]]; then
    _log "Report failed."
    return 1
  fi

  _log "Script schedule_574 success. Executed tasks: discovery, auth, twamp, tcp and report." 
}

_schedule_setup(){
  # load config
  source "$_config"
  _log "Loaded config '$_config': BASEDIR=$BASEDIR KEEPREPORT=$KEEPREPORT DISCOVERY_ENDPOINT=$DISCOVERY_ENDPOINT TWAMPC=$TWAMPC TCPC=$TCPC"

  # create report directory
  _dir=$BASEDIR/$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p $_dir
}

_schedule_cleanup(){
  # delete report directory
  if [ "$KEEPREPORT" = false ]; then
    rm -fr $_dir
  fi
}

_log(){
  logger "[$0] $1"
}

# always execute entry point
schedule "$@"
