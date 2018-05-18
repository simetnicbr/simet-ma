#!/bin/bash
#
# Execution:
# ./task_authentication.sh --agent aba55dac-6397-4027-a679-cab5e73680e5 --endpoint https://docker.lab.simet.nic.br/measure/jwt
#
# Dependencies:
# - curl
# - jq
# - logger
#

auth(){
  local _agent="undefined" 
  local _endpoint="undefined"
  local _resp="undefined"
  local _pos="undefined"
  local _token="undefined"

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --agent)
        _agent=$2
        ;;
      --endpoint)
        _endpoint=$2
        ;;
    esac
    shift
  done

  # request autentication token from API
  _resp=$(curl \
    --request POST \
    --header "X-Simet-Device: $_agent" \
    --silent \
    --fail \
    --location \
    "$_endpoint" 2>&1 
  )
  if [[ $? -ne 0 ]]; then
    # Repeat the HTTP request to obtain detailed Curl traces.
    # The original request outputs only the HTTP response, that will be parsed.
    _log "POST $_endpoint with header 'X-Simet-Device: $_agent' failed. See the HTTP Trace in the following log lines."
    _resp=$(curl \
      --request POST \
      --header "X-Simet-Device: $_agent" \
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

  # parse JSON response for attribute 'token'
  _token=$(echo "$_resp" | jq .token 2>&1 | tr -d \")
  if [[ $? -ne 0 ]]; then 
    _log "Parsing attribute 'token' failed for Json: $_resp"
    return 1
  fi
  _log "Auth token obtained: $_token"
  echo "$_token"
}

_log(){
  logger "[$0] $1"
}

# test if script is being called or sourced
if [[ $(basename ${0//-/}) == "task_authentication.sh" ]]; then
  auth "$@"
fi
