#shellcheck shell=ash
# Copyright (c) 2018 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

_error(){
  echo "ERROR: $1"
}

_info(){
  echo "INFO: $1"
}

_debug(){
  if [ "$DEBUG" = "true" ]; then
    echo "DEBUG: $1"
  fi
}

_log(){
  _info "$1"
}
# keep line
