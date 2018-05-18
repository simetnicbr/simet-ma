#!/bin/bash
#
# Execution:
# ./task-discovery --endpoint ./response.discovery.json
# ./tast-discovery --endpoint https://api.simet.nic.br/services/server_list
#
# Dependencies:
# - curl
# - jq
# - logger
#

discovery(){
  local _endpoint="undefined"
  local _resp="undefined"
  local _pos="undefined"
  local _host="undefined"
  local _port="undefined"
  local _path="undefined"
  
  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --endpoint)
        _endpoint=$2
        ;;
    esac
    shift
  done

  # main steps
  _discovery_fetch
  if [[ $?  -ne 0 ]]; then
    return 1
  fi
  _discovery_parse
  if [[ $?  -ne 0 ]]; then
    return 1
  fi
  _log "Discovery result: TWAMP_HOST=$TWAMP_HOST TWAMP_PORT=$TWAMP_PORT TCP_ENDPOINT=$TCP_ENDPOINT AUTH_ENDPOINT=$AUTH_ENDPOINT REPORT_ENDPOINT=$REPORT_ENDPOINT"
}

_discovery_fetch(){
  # fetch from local file, as param --endpoint contains a local file name
  if [[ -e "$_endpoint" && -f "$_endpoint" ]]; then
    _resp=$(cat $_endpoint| jq . 2>&1)
    if [[ $? -ne 0 ]]; then
      _log "Failed to read pre-canned discovery response from file '$_endpoint'. Response: $_resp"
      return 1
    fi
  # fetch from the remote API, as param --endpoint does NOT contain a local file name
  else
    _resp=$(curl \
      --request GET \
      --silent \
      --fail \
      --location \
      --show-error \
      "$_endpoint" 2>&1 
    )
    if [[ $? -ne 0 ]]; then
      # Repeat the HTTP request to obtain detailed Curl traces.
      # The original request outputs only the HTTP response, that will be parsed.
      _log "GET $_endpoint failed. See the HTTP Trace in the following log lines."
      _resp=$(curl \
        --request GET \
        --silent \
        --fail \
        --location \
        --verbose \
        "$_endpoint" 2>&1 
      )
      for _pos in $(seq 0 900 ${#_resp}); do
        _log "HTTP Trace: ${_resp:$_pos:$(expr $_pos + 899)}"     
      done
      return 1
    fi
  fi
}

_discovery_parse(){
  _pos=0

  TWAMP_HOST=$(echo "$_resp" | jq ".[$_pos].twamp[0].hostname" | tr -d \")
  TWAMP_PORT=$(echo "$_resp" | jq ".[$_pos].twamp[0].ports[0]" | tr -d \")

  _host=$(echo "$_resp" | jq ".[$_pos].tcp[0].hostname" | tr -d \")
  _port=$(echo "$_resp" | jq ".[$_pos].tcp[0].ports[0]" | tr -d \")
  _path=$(echo "$_resp" | jq ".[$_pos].tcp[0].basePath" | tr -d \")
  TCP_ENDPOINT="https://$_host:$_port/$_path/control"

  _host=$(echo "$_resp" | jq ".[$_pos].measureToken[0].hostname" | tr -d \")
  _port=$(echo "$_resp" | jq ".[$_pos].measureToken[0].ports[0]" | tr -d \")
  _path=$(echo "$_resp" | jq ".[$_pos].measureToken[0].basePath" | tr -d \")
  AUTH_ENDPOINT="https://$_host:$_port/$_path/jwt"

  _host=$(echo "$_resp" | jq ".[$_pos].collector[0].hostname" | tr -d \")
  _port=$(echo "$_resp" | jq ".[$_pos].collector[0].ports[0]" | tr -d \")
  _path=$(echo "$_resp" | jq ".[$_pos].collector[0].basePath" | tr -d \")
  REPORT_ENDPOINT="https://$_host:$_port/$_path/measure"
  
  # TODO validar discovery via regex
}

_log(){
  logger "[$0] $1"
}

# test if script is being called or sourced
if [[ $(basename ${0//-/}) == "task_discovery.sh" ]]; then
  discovery "$@"
fi
