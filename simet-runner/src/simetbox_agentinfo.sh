#shellcheck shell=ash
# Copyright (c) 2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

# must NOT fail, must always set _agent_family
agentinfo() {
  _agent_family="embedded"
  _agent_envname=$(sed -nE -e "/DISTRIB_DESCRIPTION/ { s/[^=]+=// ; s/^[\'\"]// ; s/[\'\"]$// ; p }" /etc/openwrt_release) || :
  _agent_envversion=$(cat /etc/openwrt_version) || :
  :
}
# keep line
