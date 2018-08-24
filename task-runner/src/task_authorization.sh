################################################################################
#
# function authorization()
# - input param: endpoint_base agent_token
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
  local _endpoint="$1/measure-allowed"
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
}
# keep line
