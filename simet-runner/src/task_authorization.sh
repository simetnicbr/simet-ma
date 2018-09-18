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
#
################################################################################

authorization() {
  if [ "$MOCK_AUTHORIZATION" = "true" ]; then
  _debug "Mocking authorization request, with allow."
    AUTHORIZATION_TOKEN="mocked_authorization_token"
    return 0  
  fi

  local _endpoint="${1}measure-allowed"
  local _agent_token="$2"

  _resp=$(curl \
    --request GET \
    --header "Authorization: Bearer $_agent_token" \
    --silent \
    --fail \
    --location \
    --show-error \
    --verbose \
    --url "$_endpoint" 2>&1
  )|| {
    # The original request already outputs Curl traces, as the HTTP response, won't be parsed.
    _log "POST $_endpoint failed. See the HTTP Trace in the following log lines."
    _log "HTTP Trace: ${_resp}"
    return 1
  }
  AUTHORIZATION_TOKEN="$_resp"
}
# keep line
