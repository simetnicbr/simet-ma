#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

do_log(){
  local pri="$1"
  shift
  [ -n "$LOG_TO_SYSLOG" ] && \
    logger -t simet-ma -p "daemon.$pri" "$*"
  case $pri in
  err|error)
    printf "%s: error: %s\n" "$0" "$*"
    ;;
  info|notice)
    printf "%s: %s\n" "$0" "$*"
    ;;
  *)
    printf "%s: %s: %s\n" "$0" "$pri" "$*"
    ;;
  esac
}

log_error(){
  do_log err "$@" >&2
}

log_info(){
  [ "$QUIET" != "true" ] && do_log info "$@"
  :
}

log_notice(){
  [ "$QUIET" != "true" ] && do_log notice "$@"
  :
}

log_debug(){
  [ "$DEBUG" = "true" ] && do_log debug "$@"
  :
}

log_measurement(){
  log_info "starting measurement task: $*"
}
log_verbose(){
  [ "$VERBOSE" = "true" ] && log_info "$@"
  :
}
log_important(){
  do_log notice "$@"
}
# keep line
