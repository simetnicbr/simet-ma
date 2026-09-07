#!/bin/sh
# SIMET-MA debian packaging helpers library
# Copyright (c) 2026 by NIC.br
#
# Distributed under the GPLv3+ license with additional terms and permissions
# Refer to the COPYING file on the program source for details

simet_deb_generate_crond() {
  RND=$(/opt/simet/bin/simet_read_vlabel.sh) || RND=
  [ -z "$RND" ] && [ -n "$AGENT_ID_FILE" ] && {
    RND=$(sed -n '1 { p; q; }' < "$AGENT_ID_FILE") 2>/dev/null || RND=
  }
  [ -z "$RND" ] && [ -r /proc/sys/kernel/random/boot_id ] && {
    RND=$(cat /proc/sys/kernel/random/boot_id) 2>/dev/null || RND=
  }
  [ -z "$RND" ] && [ -r /proc/sys/kernel/random/uuid ] && {
    RND=$(cat /proc/sys/kernel/random/uuid) 2>/dev/null || RND=
  }

  #shellcheck disable=SC2015
  RND=$(printf "%s" "$RND" | sha256sum 2>/dev/null) \
    && { RND1=$(printf "%d" "$(printf "%s" "$RND" | sed -E 's/^(.{5}).*/0x\1/')")     2>/dev/null ; } \
    && { RND2=$(printf "%d" "$(printf "%s" "$RND" | sed -E 's/^.{5}(.{5}).*/0x\1/')") 2>/dev/null ; } \
    && RND1=$(( RND1 % 60 )) && RND2=$(( RND2 % 24 )) \
    && [ "$RND1" -ge 0 ] && [ "$RND2" -ge 0 ] \
    || { RND1=50 ; RND2=5 ; }
  cat <<- CRONDEOF
	# SIMET Measurement Agent
	# Any changes to this file might be lost on package update

	MAILTO=""

	# Renew SIMET device authorization tokens and agent-id
	# Renova autorização e identificação da sonda SIMET
	$RND1 $RND2 * * * nicbr-simet if [ -x /opt/simet/bin/simet_register_ma.sh ] ; then /opt/simet/bin/simet_register_ma.sh >/dev/null ; fi

	# Geolocate if cache too old (and geolocation is enabled)
	# Geolocaliza se o cache estiver velho (e geolocalização estiver habilitada)
	$RND1 0-23/4 * * * root if [ -x /opt/simet/bin/simet_geolocation.sh ] ; then /opt/simet/bin/simet_geolocation.sh >/dev/null 2>&1 || true ; fi
	CRONDEOF
  :
}

simet_replace_crond_if_changed()
(
  . /opt/simet/lib/simet/simet_lib_config.sh >/dev/null 2>&1 </dev/null || return 1
  TMPCROND=$(mktemp -q -t simet-lmap-fetchsched.$$.XXXXXXXXXX 2>/dev/null) && {
    [ -w "$TMPCROND" ] && simet_deb_generate_crond >> "$TMPCROND" 2>/dev/null && {
      oldsha=$(sha256sum /etc/cron.d/simet-ma 2>/dev/null | sed -n '1 { s/[[:blank:]].*// ; p ; q }') || oldsha=
      newsha=$(sha256sum "$TMPCROND" 2>/dev/null | sed -n '1 { s/[[:blank:]].*// ; p ; q }') || newsha=
      [ "$oldsha" != "$newsha" ] && mv -f "$TMPCROND" /etc/cron.d/simet-ma && chmod 0644 /etc/cron.d/simet-ma
    } || rm -f "$TMPCROND"
  }
)
