#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

log_error(){
  echo "ERROR: $*" >&2
}

log_info(){
  [ "$QUIET" != "true" ] && echo "INFO: $*"
  :
}

log_notice(){
  [ "$QUIET" != "true" ] && log_info "$@"
  :
}

log_debug(){
  [ "$DEBUG" = "true" ] && echo "DEBUG: $*"
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
  QUIET= log_notice "$@"
}
# keep line
