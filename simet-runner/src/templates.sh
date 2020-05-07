#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function task_template()
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
  [ -n "$MEASUREMENT_CONTEXT" ] && _task_ctx_tag="simet.nic.br_measurement-context:$MEASUREMENT_CONTEXT,"
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

# task_json_template "filename" "URN" "column name" ... > tables/result.json
task_json_template(){
  _helper_measurement_context_tag
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

  while [ $# -ge 3 ] ; do
    FN="$1"
    FURN="$2"
    FCOL="$3"
    shift 3

    echo "{\"function\":[{\"uri\":\"$FURN\"}],"
    echo " \"column\":[\"$FCOL\"],\"row\":["
    sed -e 's/[\]/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/^/{"value":["/' -e '$ s/$/"]}/' -e '$! s/$/"]},/' -e 's/[[:cntrl:]]*//g' \
      < "$FN"
  echo ']}'
  [ $# -gt 0 ] && echo ','
  :
  done

  cat << EOF2TASKJSONTEMPLATE
  ]
}
EOF2TASKJSONTEMPLATE
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

