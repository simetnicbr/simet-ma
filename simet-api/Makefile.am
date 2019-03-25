## Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.  In every case, additional
## restrictions and permissions apply, refer to the COPYING file in the
## program Source for details.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License and the COPYING file in the program Source
## for details.

simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet
simetlmapqueuedir=$(simetlibdir)/lmap/queue
simetlmapregistrydir=$(simetlibdir)/lmap/registry.d
simetlmapconfigdir=$(simetlibdir)/lmap/config.d
EXTRA_DIST=
CLEANFILES=

if SIMETBOX_BUILD
dist_bin_SCRIPTS = simetbox_register_ma.sh simetbox_lmap-fetch-schedule.sh
sbprefix = simetbox
jsonfilter=jsonfilter
else
dist_bin_SCRIPTS = simet_register_ma.sh simet-ma_periodic.sh simet_lmap-fetch-schedule.sh
sbprefix = simet
jsonfilter=$(bindir)/jsonpath
endif

%.sh: %.sh.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" \
	    "$^" > "$@"

%.conf: %.conf.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" \
	    "$^" > "$@"

%.json: %.json.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    "$^" > "$@"

# _SCRIPT "sources" need to go in EXTRA_DIST, and the scripts themselves in CLEANFILES
EXTRA_DIST += simetbox_register_ma.sh.in simet_register_ma.sh.in
EXTRA_DIST += simet-ma_periodic.sh.in
EXTRA_DIST += simetbox_lmap-fetch-schedule.sh.in simet_lmap-fetch-schedule.sh.in
CLEANFILES += $(dist_bin_SCRIPTS)

# Ensures the empty directories we don't create at runtime do exist
install-data-local:
	$(MKDIR_P) -m 0711 -- "$(DESTDIR)$(simetconfdir)"
	$(MKDIR_P) -m 0755 -- "$(DESTDIR)$(simetconfdir)/lmap"
	$(MKDIR_P) -m 0770 -- "$(DESTDIR)$(simetlibdir)/lmap/queue"

dist_simetlib_DATA = conf/simet-ma.conf agent-version.txt conf/lmap-default-schedule.json
EXTRA_DIST += conf/simet-ma.conf.in conf/lmap-default-schedule.json
CLEANFILES += conf/simet-ma.conf agent-version.txt

dist_simetlmapregistry_DATA = registry.d/simet-ma_base-registry.json
dist_simetlmapconfig_DATA   = config.d/simet-ma_base-config.json
EXTRA_DIST += registry.d/simet-ma_base-registry.json.in config.d/simet-ma_base-config.json.in
CLEANFILES += registry.d/simet-ma_base-registry.json config.d/simet-ma_base-config.json

# Other non-source files we want in the source tarball
EXTRA_DIST += API.md

agent-version.txt:
	echo $(PACKAGE)/$(PACKAGE_VERSION) > "$@" && chmod 0644 "$@"
