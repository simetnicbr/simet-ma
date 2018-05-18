all: build

pwd=$(shell pwd)

### Build command
prepare:
	-mkdir dist
	-mkdir dist/bin
	-mkdir dist/conf

build: prepare
	$(MAKE) tcp-client-c-install
	$(MAKE) lmap-tasks-install

### Features

# tcp-client-c
tcp-client-c-subtree:
	git subtree add --prefix tcp-client-c ssh://git@code.ceptro.br:7999/simet2/tcp-client-c.git tags/v0.1.0 --squash

tcp-client-c-build:
	$(MAKE) simet -C tcp-client-c

tcp-client-c-install: tcp-client-c-build
	cp tcp-client-c/dist/bin/* dist/bin 2>/dev/null || :
	cp tcp-client-c/dist/conf/* dist/conf 2>/dev/null || :

### Dev and test commands for Alpine
dev:
	docker build environment/dev/ -t simet-agent-unix-img
	docker run \
		-it --rm \
		--name simet-agent-unix-dev \
		--mount type=bind,source="$(pwd)",target=/usr/simet-agent-unix \
	simet-agent-unix-img

dev-clean:
	-rm -rf dist

dev-install:
	# alpine -mkdir -p dist/{bin,conf}

	$(MAKE) tcp-client-c-install

# tcp-client-c for DEV
tcp-client-c-run:
	(./dist/bin/tcpc -c "http://docker.lab.simet.nic.br:8800/tcp-control" -h "docker.lab.simet.nic.br" -j "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM" 2> dist/bin/err.log)


################################################################################
# lmap-tasks
################################################################################

# Common lmap tasks for simet-agent-unix (server discovery, jwt authentication, report sending).
# Currently includes an orchestration script, while the lmap scheduler is pending work.
# All lmap tasks are inlined into this orchestration script (lmap_schedule_574.sh).
lmap-tasks-subtree:
	git subtree add --prefix lmap-tasks ssh://git@code.ceptro.br:7999/simet2/simet-agent-lmap-tasks.git tags/v0.3.0 --squash

lmap-tasks-build:
	$(MAKE) simet -C lmap-tasks

lmap-tasks-install: lmap-tasks-build
	cp lmap-tasks/dist/bin/* dist/bin 2>/dev/null || :
	cp lmap-tasks/dist/conf/* dist/conf 2>/dev/null || :

# lmap-tasks for DEV
lmap-tasks-run:
	(./dist/bin/lmap_schedule_574.sh --config ./dist/conf/lmap_schedule_574.conf 2> dist/bin/err.log)
