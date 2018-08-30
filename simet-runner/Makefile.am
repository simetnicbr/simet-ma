simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet

if SIMETBOX_BUILD
usetheshell=/bin/sh
else
usetheshell=/bin/bash
endif

dist_bin_SCRIPTS = simet-ma_run.sh
CLEANFILES = simet-ma_run.sh
dist_simetlib_DATA = src/template/report.template src/template/task.template

EXTRA_DIST = autogen.sh version

simet-ma_run.sh: src/log.sh \
		src/task_authentication.sh  \
		src/task_authorization.sh  \
		src/task_discover.sh \
		src/task_geolocation.sh \
		src/vendor/sempl.sh \
		src/task_report.sh \
		src/main.sh
	( echo "#!$(usetheshell)" ; cat $^ ) > "$@" && chmod +x "$@"


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
	cp ./test/agent-id.lab		./dist/agent-id
	cp ./test/agent.jwt.lab		./dist/agent.jwt
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
