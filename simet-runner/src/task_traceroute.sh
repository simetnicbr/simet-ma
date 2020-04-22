#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

# Connected to twamp, so enabled/disabled through TWAMP
_task_traceroute(){
  local _af="$1"
  if [[ "$_af" != "4" && "$_af" != "6" ]]; then
    log_error "Aborting task traceroute IPvX. Unknown address familiy '$_af'."
    return 1
  fi
  if [[ -z "$TRACEROUTE_HELPER" || "$TRACEROUTE_HELPER" = "NO" || "$TRACEROUTE_HELPER" = "no" || "$TRACEROUTE_HELPER" = "No" ]]; then
    log_info "Skipping task traceroute IPv$_af"
    return 0
  fi
  log_measurement "traceroute IPv$_af"
  local _host=$( discover_service TRACEROUTE HOST )

  export _task_name="${LMAP_TASK_NAME_PREFIX}tool_traceroute"
  export _task_version="$PACKAGE_VERSION"
  export _task_dir="$BASEDIR/report/traceroute-ipv$_af"
  export _task_action="traceroute_to-simet-measurement-peer_ip$_af"
  export _task_parameters='{ "host": "'$_host'" }'
  export _task_options='[]'
  export _task_extra_tags="\"simet.nic.br_peer-name:$_host\","
  export _task_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  mkdir -p "$_task_dir/tables"
  if haspipefail && [ "$VERBOSE" = "true" ] ; then
    set -o pipefail
    eval "$TRACEROUTE_HELPER -n -$_af $_host 3>&2 2>&1 1>&3 3<&- >\"$_task_dir/tables/traceroute.json\"" | tee "$_task_dir/tables/stderr.txt"
    export _task_status="$?"
    set +o pipefail
  else
    eval "$TRACEROUTE_HELPER -n -$_af $_host >\"$_task_dir/tables/traceroute.json\"" 2>"$_task_dir/tables/stderr.txt"
    export _task_status="$?"
  fi
  export _task_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [ "$_task_status" -ne 0 ]; then
    log_error "Task traceroute IPv$_af, failed with exit code: $_task_status"
    [ -s "$_task_dir/tables/stderr.txt" ] && \
      error_template < "$_task_dir/tables/stderr.txt" > "$_task_dir/tables/stderr.json" && \
      rm -f "$_task_dir/tables/stderr.txt"
#   rm -f "$_task_dir/tables/traceroute.json"
  else
    rm -f "$_task_dir/tables/stderr.txt"
  fi
  task_template > "$_task_dir/result.json"
  log_debug "End Task traceroute IPv$_af"
}

# keep line
