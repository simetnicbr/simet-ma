#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function authentication()
# - input var: AGENT_ID_FILE, AGENT_TOKEN_FILE
# - output var: AGENT_ID, AGENT_TOKEN
# - exit 1, on missing input var or files
#
# Execution:
#  echo myagentid > /tmp/agent_id
#  echo myagenttoken > /tmp/agent_token
#  AGENT_ID_FILE=/tmp/agent_id AGENT_TOKEN_FILE=/tmp/agent_token ./task_authentication.sh
#
# Dependencies:
# - none
#
################################################################################

authentication() {
  AGENT_ID=$( _authentication_agent_id ) 
  AGENT_TOKEN=$( _authentication_agent_token ) 
}

_authentication_agent_id(){
  if [ "$AGENT_ID_FILE" = "" ]; then
    log_error "Exit. Missing configuration 'AGENT_ID_FILE'."
    exit 1
  fi

  if [ ! -e "$AGENT_ID_FILE" ]; then
    log_error "Exit. 'AGENT_ID_FILE' $AGENT_ID_FILE does not exist."
    exit 1
  fi
  cat "$AGENT_ID_FILE"
}

_authentication_agent_token(){
  if [ "$AGENT_TOKEN_FILE" = "" ]; then
    log_error "Exit. Missing configuration 'AGENT_TOKEN_FILE'."
    exit 1
  fi

  if [ ! -e "$AGENT_TOKEN_FILE" ]; then
    log_error "Exit. 'AGENT_TOKEN_FILE' $AGENT_TOKEN_FILE does not exist."
    exit 1
  fi
  cat "$AGENT_TOKEN_FILE"
}

# execute main function, when script is executed directly
if [ $(basename ${0//-/}) = "task_authentication.sh" ]; then
  source ./log.sh
  authentication "$@"
  log_info "$AGENT_ID"
  log_info "$AGENT_TOKEN"
fi
# keep line
