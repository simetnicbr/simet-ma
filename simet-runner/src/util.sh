#shellcheck shell=ash
# Copyright (c) 2022 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

# space-separated list append, with space trimming
append_list() {
  printf "%s" "$*" | sed -e 's/^[ \t\n]*//' -e 's/[ \t\n]*$//' || :
}

condwait() {
  [ -n "$SERIALIZE_DISABLE" ] && {
    wait || return $?
    return 0
  }
  [ -n "$SERIALIZE_MEMLIMIT" ] && [ "$SERIALIZE_MEMLIMIT" -gt 0 ] 2>/dev/null && {
    [ "$(awk \
      'BEGIN                 { MAV=99999999 } ;
       /^MemAvailable:.*kB$/ { MAV=$2 } ;
       END                   { print MAV }' \
	 /proc/meminfo || printf 0)" -ge "$SERIALIZE_MEMLIMIT" \
    ] 2>/dev/null || {
      wait || return $?
      return 0
    }
  }
  sleep 1
  :
}

# keep line
