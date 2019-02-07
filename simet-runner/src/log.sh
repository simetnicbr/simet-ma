#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

log_error(){
  echo "ERROR: $1"
}

log_info(){
  echo "INFO: $1"
}

log_debug(){
  if [ "$DEBUG" = "true" ]; then
    echo "DEBUG: $1"
  fi
}

log(){
  log_info "$1"
}
# keep line
