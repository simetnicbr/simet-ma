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
  # sourcing is not necessary after build (make dev / make prod / make simet)
  # the build process concatenates all dependency files 
  # uncomment this line if you want to exexute this script "task_report.sh" in isolation
  if [[ $(basename ${0//-/}) == "task_report.sh" ]]; then
    source ./src/vendor/sempl
  fi
  
  _log "Going to render template '$_template'"

  # log which tables will be included in the report
  # inside the report template the same expressions are evaluated to find the included tables.
  local _table_first=$(find $_tabledir -mindepth 1 -maxdepth 1 | head -n1)
  local _table_follow=$(find $_tabledir -mindepth 1 -maxdepth 1 | (read; cat))
  _log "Report includes leading table: $_table_first"
  _log "Report includes tailing tables: $_table_follow"

  # export the variables to be interpolated in the report template
  # variable export is necessary as the template engine (called "_sempl") forks a new shell
  export _tabledir=$_tabledir 
  # render report
  _sempl $_template "$_tabledir/_report.json"
  if [[ $? -ne 0 ]]; then
    _log "Report rendering failed for template '$_template'. Result: $_report"
    return 1
  fi
  _log "Report saved for debugging: $_tabledir/_report.json"
  _report=$(cat $_tabledir/_report.json)
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
