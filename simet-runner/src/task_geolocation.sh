#shellcheck shell=ash
# Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function geolocate()
# - input param: GEOLOCATE (simet_geolocation.sh full path)
# - output: json to stdout when successful
#           simet_geolocation.sh debug output to stderr
# - return 0, geolocate metric json sent to stdout
# - return 1, no geolocation metric available
#
# Dependencies:
# - simet_geolocation.sh
# - jsonfilter (configured as $JSONFILTER)
#
################################################################################

geolocate() {
  GEOLOCATE=${GEOLOCATE:-simet_geolocation.sh}

  command -v $GEOLOCATE >/dev/null 2>&1 || return 1
  GEO=$($GEOLOCATE) || return 1
  GEO_UTIME=$(echo "$GEO" | sed -n -e '1 p')
  GEO_LAT=$(echo "$GEO" | sed -n -e '2 {s/ .*// ; p}')
  GEO_LNG=$(echo "$GEO" | sed -n -e '2 {s/^ *[^ ]\+ *// ; s/ *[^ ]\+ *$// ; p}')
  GEO_ACC=$(echo "$GEO" | sed -n -e '2 {s/^ *[^ ]\+ \+[^ ]\+ *// ; p}')
  cat << EOFGEOLOCATE
{
  "function": [ { "uri": "urn:ietf:metrics:perf:Priv_SPMonitor_Active_SIMET-GeolocationAPI-WatchPosition__Multiple_Raw" } ],
  "column":   [ "timestamp", "latitude", "longitude", "accuracy" ],
  "row": [ { "value": [ "$GEO_UTIME", "$GEO_LAT", "$GEO_LNG", "$GEO_ACC" ] } ]
}
EOFGEOLOCATE
  :
}
# keep line
