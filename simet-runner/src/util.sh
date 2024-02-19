#shellcheck shell=ash
# Copyright (c) 2022 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

# space-separated list append, with space trimming
append_list() {
  printf "%s" "$*" | sed -e 's/^[ \t\n]*//' -e 's/[ \t\n]*$//' || :
}

# keep line
