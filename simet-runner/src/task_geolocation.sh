#shellcheck shell=ash
# Copyright (c) 2018,2019 NIC.br  <medicoes@simet.nic.br>
# Source code fraction, for license information refer to the
# main program source code.

################################################################################
#
# function geolocate()
# - input param: GEOLOCATE (simet_geolocation.sh full path)
#   - needs simet_geolocation API v2 (LMAP-like output)
# - output: json to stdout when successful
#           simet_geolocation.sh debug output to stderr
# - return 0, geolocate metric json sent to stdout
# - return 1, no geolocation metric available
#
# Dependencies:
# - simet_geolocation.sh
#
################################################################################

geolocate() {
  GEOLOCATE=${GEOLOCATE:-simet_geolocation.sh}
  GEOSCRIPT=$(command -v "$GEOLOCATE") || return 1
  $GEOSCRIPT || return $?
  :
}
# keep line
