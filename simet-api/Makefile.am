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

# Note: if the defines below are modified, please grep -r all the
# simet-ma source to ensure they are in sync everywhere!
simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet
simetrundir=$(localstatedir)/run/simet
simetpubrundir=$(localstatedir)/run/simet_public
simetlmapqueuedir=$(localstatedir)/spool/lmapd/queue
simetlmapregistrydir=$(simetlibdir)/lmap/registry.d
simetlmapconfigdir=$(simetlibdir)/lmap/config.d
simetlmapbindir=$(simetlibdir)/lmap/bin
EXTRA_DIST=
CLEANFILES=

## FIXME: autoconfize this
simetenginename=nic_simet2_simet-ma

if SIMETBOX_BUILD
dist_bin_SCRIPTS = simetbox_lmap-fetch-schedule.sh simetbox_fping-to-gateway.sh
sbprefix = simetbox
jsonfilter=jsonfilter
theshell=/bin/sh
else
dist_bin_SCRIPTS = simet_lmap-fetch-schedule.sh
sbprefix = simet
jsonfilter=$(bindir)/jsonpath
theshell=/bin/bash
endif

EXTRA_DIST += simetbox_lmap-fetch-schedule.sh.in simet_lmap-fetch-schedule.sh.in
EXTRA_DIST += simetbox_fping-to-gateway.sh.in

dist_bin_SCRIPTS += simet_register_ma.sh simet_geolocation.sh
EXTRA_DIST += simet_register_ma.sh.in simet_geolocation.sh.in
dist_bin_SCRIPTS += simet_lmap-send-report.sh simet_lmap-stdout-wrapper.sh
EXTRA_DIST += simet_lmap-send-report.sh.in simet_lmap-stdout-wrapper.sh.in

simet_read_vlabel.sh.in : simet_read_vlabel.$(sbprefix).sh.in
	ln -sf "$^" "$@"

simet_create_vlabel.sh.in : simet_create_vlabel.$(sbprefix).sh.in
	ln -sf "$^" "$@"

dist_bin_SCRIPTS += simet_read_vlabel.sh simet_create_vlabel.sh
EXTRA_DIST += simet_read_vlabel.simetbox.sh.in simet_read_vlabel.simet.sh.in
EXTRA_DIST += simet_create_vlabel.simetbox.sh.in simet_create_vlabel.simet.sh.in
CLEANFILES += simet_read_vlabel.sh.in simet_read_vlabel.sh
CLEANFILES += simet_create_vlabel.sh.in simet_create_vlabel.sh

# LMAP wrapped tasklet links we want to create, watch the first field (-, exec21-, etc)
if SIMETBOX_BUILD
traceroute_tasklets = --help_ICMP-traceroute_traceroute
traceroute_tasklets += --help_UDP-traceroute_udp-traceroute --help_ICMP-traceroute_icmp-traceroute
tasklets = exec21ok-v_fping-to-host-raw_fping --help__ping --help__ping6 --help__nslookup -v__drill -v__dig
else
traceroute_tasklets = -V_ICMP-traceroute_traceroute
traceroute_tasklets += -V_UDP-traceroute_udp-traceroute -V_ICMP-traceroute_icmp-traceroute
tasklets = exec21ok-v_fping-to-host-raw_fping -V__ping -V__ping6 -version__nslookup -v__drill -v__dig
endif

dist_simetlmapbin_SCRIPTS = lmap-tasks/lmap-wrapper.sh lmap-tasks/simet2-agent-info.sh lmap-tasks/lmap-traceroute-wrapper.sh
EXTRA_DIST += lmap-tasks/lmap-wrapper.sh.in lmap-tasks/simet2-agent-info.sh.in lmap-tasks/lmap-traceroute-wrapper.sh.in
CLEANFILES += $(dist_simetlmapbin_SCRIPTS)

# automake will nicely "resolve" our symlinks, thus wasting space.
# we use the install-exec-hook to create the symlinks to lmap-wrapper.sh
tasklets_ln := $(patsubst %,lmap-task%,$(tasklets))

# and the same for the traceroute wrapper
traceroute_tasklets_ln := $(patsubst %,lmap-task%,$(traceroute_tasklets))

# Dynamically build the registry of tasklets and their tasks
registry.d/simet-ma_tasklet-registry.json :
	{ echo '{"ietf-lmap-control:lmap":{"capabilities":{' ; \
	echo ' "tasks":{"task":[' ; \
	{ for i in $(tasklets) $(traceroute_tasklets) ; do \
		tn1="$${i#*_}" ; tn="simet.nic.br_tool_$${tn1#*_}" ; \
		pn="lmap-task$${i}" ; \
		echo "  {\"name\":\"$${tn}\",\"program\":\"$(simetlmapbindir)/$${pn}\"}," ; \
	done ; } | sed -e '$$ s/,$$//' ; \
	echo ']}}}}' ; \
	} > "$@"

config.d/simet-ma_tasklet-config.json :
	{ echo '{"ietf-lmap-control:lmap":{"tasks":{"task":[' ; \
	{ for i in $(tasklets) $(traceroute_tasklets) ; do \
		tn1="$${i#*_}" ; tn="simet.nic.br_tool_$${tn1#*_}" ; \
		pn="lmap-task$${i}" ; \
		echo "  {\"name\":\"$${tn}\"," ; \
		echo "   \"tag\":[\"simet.nic.br_engine-name:$(simetenginename)\"," ; \
		echo "          \"simet.nic.br_engine-version:$(PACKAGE_VERSION)\"," ; \
		echo "          \"simet.nic.br_task-version:$(PACKAGE_VERSION)\"]," ; \
		echo "   \"program\":\"$(simetlmapbindir)/$${pn}\"}," ; \
	done ; } | sed -e '$$ s/,$$//' ; \
	echo ']}}}' ; \
	} > "$@"

%.sh: %.sh.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@SIMETRUNDIR@!$(simetrundir)!g" -e "s!@SIMETPUBRUNDIR@!$(simetpubrundir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" -e "s!@PACKAGEVERSION@!$(PACKAGE_VERSION)!g" \
	    -e "s!@SIMET_ENGINE_NAME@!$(simetenginename)!g" -e "s!@LMAPBINDIR@!$(simetlmapbindir)!g" \
	    -e "1 s!/bin/\(ba\)\?sh!$(theshell)!" \
	    "$^" > "$@" && chmod 0755 "$@"

%.conf: %.conf.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@SIMETRUNDIR@!$(simetrundir)!g" -e "s!@SIMETPUBRUNDIR@!$(simetpubrundir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" -e "s!@PACKAGEVERSION@!$(PACKAGE_VERSION)!g" \
	    -e "s!@SIMET_ENGINE_NAME@!$(simetenginename)!g" -e "s!@LMAPBINDIR@!$(simetlmapbindir)!g" \
	    "$^" > "$@"

%.json: %.json.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@SIMETRUNDIR@!$(simetrundir)!g" -e "s!@SIMETPUBRUNDIR@!$(simetpubrundir)!g" \
	    -e "s!@LMAPQUEUEDIR@!$(simetlmapqueuedir)!g" -e "s!@SBPREFIX@!$(sbprefix)!g" \
	    -e "s!@PACKAGEVERSION@!$(PACKAGE_VERSION)!g" -e "s!@LMAPBINDIR@!$(simetlmapbindir)!g" \
	    -e "s!@SIMET_ENGINE_NAME@!$(simetenginename)!g" \
	    "$^" > "$@"

# _SCRIPT "sources" need to go in EXTRA_DIST, and the scripts themselves in CLEANFILES
EXTRA_DIST += simet_lmap-create-report.sh.in
CLEANFILES += $(dist_bin_SCRIPTS)

# Ensures the empty directories we don't create at runtime do exist
install-data-local:
	$(MKDIR_P) -m 0711 -- "$(DESTDIR)$(simetconfdir)"
	$(MKDIR_P) -m 0755 -- "$(DESTDIR)$(simetconfdir)/lmap"
	$(MKDIR_P) -m 0770 -- "$(DESTDIR)$(simetlmapqueuedir)"

# Creates tasklet symlinks
install-exec-hook:
	$(MKDIR_P) -m 0755 -- "$(DESTDIR)$(simetlmapbindir)"
	cd "$(DESTDIR)$(simetlmapbindir)" && \
		for i in $(tasklets_ln) ; do \
			ln -sf lmap-wrapper.sh "$$i" ; \
		done
	cd "$(DESTDIR)$(simetlmapbindir)" && \
		for i in $(traceroute_tasklets_ln) ; do \
			ln -sf lmap-traceroute-wrapper.sh "$$i" ; \
		done

conf/lmap-default-schedule.json : conf/lmap-default-schedule.$(sbprefix).json
	cd conf && ln -sf lmap-default-schedule.$(sbprefix).json lmap-default-schedule.json

dist_simetlib_DATA = conf/simet-ma.conf agent-version.txt conf/lmap-default-schedule.json
EXTRA_DIST += conf/simet-ma.conf.in conf/lmap-default-schedule.simetbox.json conf/lmap-default-schedule.simet.json
CLEANFILES += conf/lmap-default-schedule.json conf/simet-ma.conf agent-version.txt

simet_lib.sh.in : simet_lib.$(sbprefix).sh.in
	ln -sf "$^" "$@"

dist_simetlib_SCRIPTS = simet_lib.sh simet_lib_config.sh
EXTRA_DIST += simet_lib.simetbox.sh.in  simet_lib.simet.sh.in simet_lib_config.sh.in
CLEANFILES += simet_lib.sh simet_lib.sh.in simet_lib_config.sh

dist_simetlmapregistry_DATA = registry.d/simet-ma_base-registry.json registry.d/simet-ma_tasklet-registry.json
dist_simetlmapregistry_DATA += registry.d/simet.nic.br_subsystem-id.tag-registry.json
EXTRA_DIST += registry.d/simet-ma_base-registry.json.in
CLEANFILES += registry.d/simet-ma_base-registry.json registry.d/simet-ma_tasklet-registry.json
dist_simetlmapconfig_DATA   = config.d/simet-ma_base-config.json config.d/simet-ma_tasklet-config.json
EXTRA_DIST += config.d/simet-ma_base-config.json.in
CLEANFILES += config.d/simet-ma_base-config.json config.d/simet-ma_tasklet-config.json

if SIMETBOX_BUILD
dist_simetlmapregistry_DATA += registry.d/simetbox_base-registry.json
dist_simetlmapconfig_DATA += config.d/simetbox_base-config.json
EXTRA_DIST += registry.d/simetbox_base-registry.json.in config.d/simetbox_base-registry.json.in
CLEANFILES += registry.d/simetbox_base-registry.json config.d/simetbox_base-registry.json
endif

# Other non-source files we want in the source tarball
EXTRA_DIST += API.md

agent-version.txt:
	echo $(PACKAGE)/$(PACKAGE_VERSION) > "$@" && chmod 0644 "$@"
