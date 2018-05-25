#
# Execution:
# ./schedule_574.sh --config ./schedule_574.conf
#
# Dependencies:
# - curl
# - jq
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
  _log "Discovery success."

  # authentication token
  auth  --agent "$AGENT" --endpoint "$AUTH_ENDPOINT"
  if [[ $? -ne 0 ]]; then
    _log "Auth failed. Skipping tasks: twamp, tcp and report."
    return 1
  fi
  _log "Authentication success. JWT_TOKEN=$JWT_TOKEN"

  # twamp metric
  if [[ "$TWAMPC" = "NO" || "$TWAMPC" = "no" || "$TWAMPC" = "No" ]]; then
    _log "Skipping TWAMP task"
  else
    _log "Starting TWAMP task"
    eval "$TWAMPC $TWAMP_SERVER > $_dir/twamp.json"
    if [[ $? -ne 0 ]]; then
      rm -f $_dir/twamp.json
      _log "TWAMP task failed. Continue with tasks: tcp, report"
    else
      _log "TWAMP success. table=$_dir/twamp.json"
    fi
  fi

  # tcp metric
  if [[ "$TCPC" = "NO" || "$TCPC" = "no" || "$TCPC" = "No" ]]; then
    _log "Skipping TCP task"
  else
    _log "Starting TCP task"
    eval "$TCPC -c $TCP_ENDPOINT -h $TCP_HOST -d $AGENT -j $JWT_TOKEN > $_dir/tcp.json"
    if [[ $? -ne 0 ]]; then
      rm -f $_dir/tcp.json
      _log "TCP task failed. Continue with task: report"
    else
      _log "TCP success. table=$_dir/tcp.json"
    fi
  fi

  # lmap reporting
  report \
    --template "$REPORT_TEMPLATE" \
    --agent "$AGENT" \
    --tabledir "$_dir" \
    --endpoint "$REPORT_ENDPOINT" \
    --jwt "$JWT_TOKEN"
  if [[ $? -ne 0 ]]; then
    _log "Report failed."
    return 1
  fi
  _log "LMAP Report Success."

  _log "Script schedule_574 success. Executed tasks: discovery, auth, twamp, tcp and report." 
}

_schedule_setup(){
  # load config
  source "$_config"
  _log "Loaded config '$_config': BASEDIR=$BASEDIR KEEPREPORT=$KEEPREPORT REPORT_TEMAPLATE=$REPORT_TEMPLATE DISCOVERY_ENDPOINT=$DISCOVERY_ENDPOINT TWAMPC=$TWAMPC TCPC=$TCPC"

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
  echo "$1"
}

# always execute entry point
schedule "$@"
