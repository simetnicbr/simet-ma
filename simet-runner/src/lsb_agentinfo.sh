#shellcheck shell=ash
# Copyright (c) 2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

# must NOT fail, must always set _agent_family.
agentinfo() {
  _agent_family="system_service"
  _agent_envname=$(lsb_release -s -i) || _agent_envname="(generic)"
  _agent_envversion=$(lsb_release -s -d) || _agent_envversion="unknown"
  :
}
# keep line
