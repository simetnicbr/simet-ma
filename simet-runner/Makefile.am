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
simetlmapbindir=$(simetlibdir)/lmap/bin

if SIMETBOX_BUILD
usetheshell=/bin/sh
agentinfo=src/simetbox_agentinfo.sh
else
usetheshell=/bin/bash
agentinfo=src/lsb_agentinfo.sh
endif

dist_bin_SCRIPTS = simet-ma_run.sh

EXTRA_DIST = autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version

# .sh.in files go in EXTRA_DIST, the corresponding .sh goes in _sources and CLEANFILES
%.sh: %.sh.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@SIMETLMAPBINDIR@!$(simetlmapbindir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" \
	    -e "s!@RUNNERNAME@!$(PACKAGE_NAME)!g" -e "s!@RUNNERVERSION@!$(PACKAGE_VERSION)!g" \
	    -e "s!@RUNNERSTRING@!$(PACKAGE_STRING)!g" \
	    "$^" > "$@"

simetma_sources = src/defines.sh \
		src/log.sh \
		src/task_authentication.sh  \
		src/task_authorization.sh  \
		src/task_discover.sh \
		src/task_geolocation.sh \
		$(agentinfo) \
		src/task_environment.sh \
		src/task_traceroute.sh \
		src/templates.sh \
		src/main.sh

simet-ma_run.sh: $(simetma_sources)
	( echo "#!$(usetheshell)" ; cat $^ ) > "$@" && chmod +x "$@"

EXTRA_DIST += $(simetma_sources) src/simetbox_agentinfo.sh src/lsb_agentinfo.sh src/defines.sh.in
CLEANFILES = simet-ma_run.sh src/defines.sh

.PHONY: help
help:
	@echo 'Management commands for simet-runner:'
	@echo
	@echo 'Usage:'
	@echo 'build Tasks:'
	@echo '    make                     Production build.'
	@echo '    make dev                 Development build.'
	@echo '    make clean               Remove build artifacts.'
	@echo 'Development Tasks:'
	@echo '    make dev-simetbox        Enter a local OpenWRT container to test synced source files.'
	@echo '    make dev-simetlinux	    Enter a local Linux container to test synced source files.'
	@echo 'Other Tasks:'
	@echo

################################################################################
# Build tasks
################################################################################

.PHONY: dev
dev: configless
	cp ./test/simet_agent_unix.conf		./dist/simet_agent_unix.conf
	cp ./test/agent-id.prod		./dist/agent-id
	cp ./test/agent.jwt.prod		./dist/agent.jwt
	cp ./test/services.mock.json		./dist/services.mock.json

.PHONY: configless
configless: clean simet-ma_run.sh
	mkdir -p ./dist
	cp simet-ma_run.sh dist/

clean-local:
	-rm -fr ./dist

################################################################################
# Development Tasks
################################################################################
.PHONY: dev-simetbox
dev-simetbox:
		docker build -t openwrt-dev . && docker run -v `pwd`:/simet-runner -w /simet-runner -it openwrt-dev /bin/ash

.PHONY: dev-debian
dev-simetlinux:
		echo "TODO"
