#shellcheck shell=ash
################################################################################
#
# Execution
# ./report.sh \
#   --template ./report.template \
#   --agent aba55dac-6397-4027-a679-cab5e73680e5 \
#   --tabledir /tmp/simet-ma/2018-05-11T21:52:50Z \
#   --endpoint https://docker.lab.simet.nic.br:443/collector/measure \
#   --jwt abc
#
# Dependencies
# - curl
# - sempl (src/vendor/sempl; https://github.com/nextrevision/sempl)
#
################################################################################

report(){
  local _template="./report.json.template"
  local _date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local _agent="undefined"
  local _macaddress="undefined"
  local _tabledir="undefined"
  local _endpoint="undefined"
  local _jwt="undefined"
  local _report="undefined"
  local _event=$_date
  local _start=$_date
  local _status="0"

  # read params
  while [ ! $# -eq 0 ]; do
    case "$1" in
      --template)
        _template=$2
	shift
        ;;
      --agent)
        _agent=$2
	shift
        ;;
      --tabledir)
        _tabledir=$2
	shift
        ;;
      --endpoint)
        _endpoint=$2
	shift
        ;;
      --jwt)
        _jwt=$2
	shift
        ;;
      --macaddress)
        _macaddress=$2
	shift
        ;;
    esac
    shift
  done

  # main steps
  _report_render_final || return 1
  _report_send
}

report_render_task_result(){
  local _task_dir="$1"
  _sempl "$_task.template" "$_task_dir/tables"
}

_report_render_final(){
  _log "Going to render template '$_template.{head,tail}'"

  # export the variables to be interpolated in the report template
  # variable export is necessary as the template engine (called "_sempl") forks a new shell
  export _tabledir
  # render report: header, cat all "tables", then the tail
  _sempl "$_template.header" "$_tabledir/_report.json" || {
    _log "Report rendering failed for template '$_template'. Result: $_report"
    return 1
  }
  local _first_table=0
  find "$_tabledir" -mindepth 1 -maxdepth 1 -print | grep -v '_report.json' | while read -r _tablefile ; do
    if [ $_first_table -eq 0 ] ; then
      _first_table=1
    else
      echo "," >> "$_tabledir/_report.json"
    fi
    _log "Including table '$_tablefile'"
    cat "$_tablefile" >> "$_tabledir/_report.json"
  done
  _sempl "$_template.tail" "$_tabledir/_report.json.tail" || {
    _log "Report rendering failed for template '$_template'. Result: $_report"
    return 1
  }
  cat "$_tabledir/_report.json.tail" >> "$_tabledir/_report.json"

  _log "Report saved for debugging: $_tabledir/_report.json"
  _report=$(cat "$_tabledir/_report.json")
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
  ) || {
    # The original request already outputs Curl traces, as the HTTP response, won't be parsed.
    _log "POST $_endpoint failed. See the HTTP Trace in the following log lines."
    _log "HTTP Trace: ${_resp}"
    return 1
  }
  _log "POST $_endpoint success."
}

_log(){
  echo "$1"
}

# run when not being sourced
if [ "${0##*/}" = "task_report.sh" ]; then
  source ./log.sh
  source ./vendor.sempl.sh
  report "$@"
fi

# keep line
