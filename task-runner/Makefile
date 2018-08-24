# .RECIPEPREFIX +=

.PHONY: help
help:
		@echo 'Management commands for simet-agent-unix/task-runner:'
		@echo
		@echo 'Usage:'
		@echo 'Development Tasks:'
		@echo '    make dev-simetbox             	Enter a local OpenWRT container to test synced source files.'
		@echo '    make dev-simetlinux	          Enter a local Linux container to test synced source files.'
		@echo 'Other Tasks:'
		@echo

################################################################################
# Build tasks
################################################################################

# Task consumed by parent simet-agent-unix
simet: prod

prod: configless

.PHONY: dev
dev: configless
	cp ./conf/simet_agent_unix.conf		./dist/simet_agent_unix.conf
	cp ./conf/agent-id.lab		./dist/agent-id
	cp ./conf/agent.jwt.lab		./dist/agent.jwt
	cp ./conf/services.mock.json		./dist/services.mock.json

.PHONY: configless
configless: clean
	mkdir -p ./dist
	( echo '#!/bin/ash' ; \
		cat ./src/log.sh ; \
		cat ./src/task_authentication.sh ; \
		cat ./src/task_authorization.sh ; \
		cat ./src/task_discover.sh ; \
		cat ./src/task_geolocation.sh ; \
		cat ./src/task_twamp.sh ; \
		cat ./src/vendor/sempl.sh; \
		cat ./src/task_report.sh ; \
		cat ./src/main.sh ) \
	>> ./dist/simet_agent_unix.sh
	chmod +x ./dist/simet_agent_unix.sh

clean:
	rm -fr ./dist

################################################################################
# Development Tasks
################################################################################
.PHONY: dev-simetbox
dev-simetbox:
		docker build -t openwrt-dev . && docker run -v `pwd`:/task-runner -w /task-runner -it openwrt-dev /bin/ash

.PHONY: dev-debian
dev-simetlinux:
		echo "TODO"