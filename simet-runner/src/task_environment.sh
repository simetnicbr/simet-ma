#shellcheck shell=ash
# Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function task_environment()
# - output: json to stdout when successful
# - return 0, metric json sent to stdout
# - return 1, failed
#
# Dependencies:
#
################################################################################


# Output metrics related to measurement agent metadata for the whole report
# We could instead report them once per task, but that wastes space since they
# are invariant during a measurement run.
ma_environment() {
  # AgentInfo metric
  agentinfo && cat << EOF1AGITEMPLATE
{
  "function": [ { "uri": "urn:ietf:metrics:perf:Priv_SPMonitor_Passive_AgentInfo__Multiple_Singleton" } ],
  "column": [ "engine_name", "engine_version", "agent_family", "agent_environment_name", "agent_environment_version" ],
  "row": [ { "value": [ "$SIMET_ENGINE_NAME", "$_task_version", "$_agent_family", "$_agent_envname", "$_agent_envversion" ] } ]
}
EOF1AGITEMPLATE
  :
}
# keep line
