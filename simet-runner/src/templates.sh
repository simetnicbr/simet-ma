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

_cat_many() {
  while [ $# -ge 2 ] ; do
    cat "$1"
    echo ","
    shift
  done
  if [ $# -ne 0 ] ; then
    cat "$1"
  fi
  :
}

task_template(){
  cat << EOF1TASKTEMPLATE
{
  "schedule": "$REPORT_SCHEDULE",
  "action": "$_task_action",
  "task": "$_task_name",
  "parameters": $_task_parameters,
  "option": $_task_options,
  "conflict": [],
  "tag": [
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

