#shellcheck shell=ash
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
