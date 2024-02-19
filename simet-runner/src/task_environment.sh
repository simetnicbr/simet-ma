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
  [ -n "$AGENTINFO_HELPER" ] && [ -x "$AGENTINFO_HELPER" ] && {
    "$AGENTINFO_HELPER" || return "$?"
    return 0
  }

  # fallback
  [ -z "$SIMET_ENGINE_NAME" ] || [ -z "$SIMET2_AGENT_FAMILY" ] || [ -z "$PACKAGE_VERSION" ] && return 1
  cat << EOF1AGITEMPLATE
{
  "function": [ { "uri": "urn:ietf:metrics:perf:Priv_SPMonitor_Passive_AgentInfo__Multiple_Singleton" } ],
  "column": [ "engine_name", "engine_version", "agent_family", "agent_environment_name", "agent_environment_version" ],
  "row": [ { "value": [ "$SIMET_ENGINE_NAME", "$(simet_jo "$PACKAGE_VERSION")", "$SIMET2_AGENT_FAMILY", "$(simet_jo "$SIMET2_AGENT_ENVNAME")", "$(simet_jo "$SIMET2_AGENT_ENVVERSION")" ] } ]
}
EOF1AGITEMPLATE
}
# keep line
