#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function task_template()
# function task_json_template()
# function report_template()
# function error_template()
#
# - input param: environment variables (see function)
# - output param: stdout, exit status
#
# Output to stdout the filled template, based on the environment vars
#
################################################################################

_helper_measurement_context_tag() {
  _task_ctx_tag=
  [ -n "$MEASUREMENT_CONTEXT" ] && \
    _task_ctx_tag="\"simet.nic.br_measurement-context:$MEASUREMENT_CONTEXT\","
  :
}

_cat_many() {
  comma=
  while [ $# -gt 0 ] ; do
    [ -s "$1" ] && grep -q "[^[:space:]]" "$1" && {
      [ -n "$comma" ] && echo ","
      cat "$1"
      comma=1
    }
    shift
  done
  :
}

task_template(){
  _helper_measurement_context_tag
  cat << EOF1TASKTEMPLATE
{
  "schedule": "$REPORT_SCHEDULE",
  "action": "$_task_action",
  "task": "$_task_name",
  "parameters": $_task_parameters,
  "option": $_task_options,
  "conflict": [],
  "tag": [ $_task_extra_tags $_task_ctx_tag
    "simet.nic.br_engine-name:${SIMET_ENGINE_NAME}",
    "simet.nic.br_engine-version:$_task_version",
    "simet.nic.br_task-version:$_task_version"${REPORT_MAC_ADDRESS_TAG_ENTRY}
  ],
  "event": "$REPORT_EVENT",
  "start": "$_task_start",
  "end": "$_task_end",
  "status": $_task_status,
  "table": [
EOF1TASKTEMPLATE
  _cat_many $(find "$_task_dir/tables" -type f -name "*.json" | sort)
  cat << EOF2TASKTEMPLATE
  ]
}
EOF2TASKTEMPLATE
  :
}

# task_json_template "URN" "filename" "column name" ["filename" "column name" ...] > tables/result.json
# single row, one or more columns.  Tolerates empty/missing files (encodes as "null").
task_json_template(){
  [ $# -lt 3 ] && return

  _helper_measurement_context_tag
  FURN="$1"
  shift
  cat << EOF1TASKJSONTEMPLATE
{
  "schedule": "$REPORT_SCHEDULE",
  "action": "$_task_action",
  "task": "$_task_name",
  "parameters": $_task_parameters,
  "option": $_task_options,
  "conflict": [],
  "tag": [ $_task_extra_tags $_task_ctx_tag
    "simet.nic.br_engine-name:${SIMET_ENGINE_NAME}",
    "simet.nic.br_engine-version:$_task_version",
    "simet.nic.br_task-version:$_task_version"${REPORT_MAC_ADDRESS_TAG_ENTRY}
  ],
  "event": "$REPORT_EVENT",
  "start": "$_task_start",
  "end": "$_task_end",
  "status": $_task_status,
  "table": [
EOF1TASKJSONTEMPLATE

  printf '{ "function": [ {"uri": "%s"} ], "column": [' "$FURN"
  ( #subshell to preserve "$@"
    local comma=
    while [ $# -ge 2 ] ; do
      [ -s "$1" ] && {
	printf ' %s"%s"' "$comma" "$2"
        comma=", "
      }
      shift 2
    done
  )
  printf '], "row": [ {"value": [\n'
  local comma=
  while [ $# -ge 2 ] ; do
    FN="$1"
    if [ -s "$FN" ] ; then
      [ -n "$comma" ] && printf ',\n'
      printf '"'
      sed -e 's/[\]/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/[[:cntrl:]]*//g' \
	< "$FN"
      printf '"'
      comma=1
    fi
    shift 2
    :
  done
  printf '\n]}\n]}\n]}\n'
  :
}

report_template(){
  cat << EOF1REPORTTEMPLATE
{ "ietf-lmap-report:report": {
    "date": "$_lmap_report_date",
    "agent-id": "$AGENT_ID",
    "result": [
EOF1REPORTTEMPLATE
  _cat_many $(find "$_report_dir" -mindepth 2 -type f -name result.json | sort)
  cat << EOF2REPORTTEMPLATE
    ]
}}
EOF2REPORTTEMPLATE
  :
}

# error_template < stderr.txt > tables/stderr.json
error_template() {
  echo '{"function":[{"uri":"urn:ietf:metrics:perf:Priv_SPMonitor_Active_stderr-output__Multiple_Raw"}],'
  echo ' "column":["stderr_line"],"row":['
  sed -e 's/[\]/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/^/{"value":["/' -e '$ s/$/"]}/' -e '$! s/$/"]},/' -e 's/[[:cntrl:]]*//g'
  echo ']}'
  :
}

