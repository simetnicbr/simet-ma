#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function authorization()
# - input param: endpoint_base agent_token
# - input var: MOCK_AUTHORIZATION (optional var)
# - output var: AUTHORIZATION_TOKEN
# - return 0, on authorization
# - return 1, on non authorization
#
# Execution:
#
# Dependencies:
# - curl
# - jsonfilter (configured as $JSONFILTER)
#
################################################################################

authorization() {
  if [ -n "$SIMET_SERVICELIST_OVERRIDE" ]; then
    log_debug "Disabling authorization token support."
    AUTHORIZATION_TOKEN=
    return 0  
  fi

  local _endpoint="${1}measure-allowed"
  local _agent_token="$2"

  curl \
    --request GET \
    --header "Authorization: Bearer $_agent_token" \
    --silent \
    --show-error \
    --fail \
    --location \
    --url "$_endpoint" > $BASEDIR/auth_response.json
  
  if [ "$?" -ne 0 ]; then
    log_error "Authorization request failed at: $_endpoint"
    return 1
  fi
 
  local _allowed=$($JSONFILTER -i $BASEDIR/auth_response.json -e "@.measureAllowed")
  if [ $_allowed != "true" ]; then
    log_error "Authorization request denied at: $_endpoint"
    return 1
  fi

  log_debug "Authorization success at: $_endpoint"
  AUTHORIZATION_TOKEN=$($JSONFILTER -i $BASEDIR/auth_response.json -e "@.measurementToken")
}
# keep line
