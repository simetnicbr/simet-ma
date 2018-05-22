#
# Execution
# ./task_report.sh \
#   --template ./report.template \
#   --agent aba55dac-6397-4027-a679-cab5e73680e5 \
#   --tabledir /tmp/schedule_574/2018-05-11T21:52:50Z \
#   --endpoint https://docker.lab.simet.nic.br:443/collector/measure \
#   --jwt abc
#
# Dependencies
# - curl
# - sempl (https://github.com/nextrevision/sempl)
#

report(){
  local _template="./report.json.template"
  local _date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local _agent="undefined"
  local _tabledir="undefined"
  local _endpoint="undefined"
  local _jwt="undefined"
  local _report="undefined"

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --template)
        _template=$2
        ;;
      --agent)
        _agent=$2
        ;;
      --tabledir)
        _tabledir=$2
        ;;
      --endpoint)
        _endpoint=$2
        ;;
      --jwt)
        _jwt=$2
        ;;
    esac
    shift
  done

  # main steps
  _report_render
  if [[ $?  -ne 0 ]]; then
    return 1
  fi
  _report_send
}

_report_render(){
  # define interpolation variables
  local _table_first=$(find $_tabledir -mindepth 1 -maxdepth 1 | head -n1)
  local _table_follow=$(find $_tabledir -mindepth 1 -maxdepth 1 | (read; cat))
  export TABLE_FOLLOW=$_table_follow

  # render report
  # source ./vendor/sempl
  _log "Going to render template '$_template'"
  _log "_table_first=$_table_first"
  _log "_table_follow=$_table_follow"
  _report=$(_sempl -o $_template)
  if [[ $? -ne 0 ]]; then
    _log "Report rendering failed for template '$_template'. Result: $_report"
    return 1
  fi

  # save report for debugging
  echo "$_report" > $_tabledir/_report.json
}

_report_send(){
  # send to lmap collector
  _resp=$(curl \
    --request POST \
    --header "Content-Type: application/yang.data+json" \
    --header "Authorization: Bearer $_jwt" \
    --data "$_report"  \
    --silent \
    --fail \
    --location \
    --show-error \
    --verbose \
    "$_endpoint" 2>&1
  )
  if [[ $? -ne 0 ]]; then
    # The original request already outputs Curl traces, as the HTTP response, won't be parsed.
    _log "POST $_endpoint failed. See the HTTP Trace in the following log lines."
    for _pos in $(seq 0 900 ${#_resp}); do
      _log "HTTP Trace: ${_resp:$_pos:$(expr $_pos + 899)}"     
    done
    return 1
  fi
  _log "POST $_endpoint success."
}

_log(){
  echo "$1"
}

# test if script is being called or sourced
if [[ $(basename ${0//-/}) == "task_report.sh" ]]; then
  report "$@"
fi
