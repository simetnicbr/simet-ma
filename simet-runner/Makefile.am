## Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
##
## This program is free software: you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation, either version 3 of the
## License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet

if SIMETBOX_BUILD
usetheshell=/bin/sh
else
usetheshell=/bin/bash
endif

dist_bin_SCRIPTS = simet-ma_run.sh
dist_simetlib_DATA = src/template/report.template src/template/task.template

EXTRA_DIST = autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version


simetma_sources = src/log.sh \
		src/task_authentication.sh  \
		src/task_authorization.sh  \
		src/task_discover.sh \
		src/task_geolocation.sh \
		src/vendor/sempl.sh \
		src/main.sh

simet-ma_run.sh: $(simetma_sources)
	( echo "#!$(usetheshell)" ; cat $^ ) > "$@" && chmod +x "$@"

EXTRA_DIST += $(simetma_sources)
CLEANFILES = simet-ma_run.sh

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
	cp ./src/template/*		./dist/

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
