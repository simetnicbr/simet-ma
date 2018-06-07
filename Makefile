### SIMET-Agent-Unix Features
# (X) tcp-client-c 
# ( ) twamp-client-c
# (X) simet-agent-lmap-tasks (DNS, Trace and HTTP tasks)


all: build

pwd=$(shell pwd)

#####################
### Build command ###
#####################
.PHONY: prepare build
prepare:
	-mkdir -p dist/bin
	-mkdir -p dist/conf

build: prepare
	# Add new feature

	$(MAKE) tcp-client-c-install
	# $(MAKE) twamp-client-c-install
	# $(MAKE) lmap-tasks-install

########################
### Install commands ###
########################
# features build and install commands

####################
### tcp-client-c ###

.PHONY: tcp-client-c-build tcp-client-c-install
# Build
tcp-client-c-build:
	$(MAKE) simet -C tcp-client-c

# Install
tcp-client-c-install: prepare tcp-client-c-build
	cp tcp-client-c/dist/bin/* dist/bin 2>/dev/null || :
	cp tcp-client-c/dist/conf/* dist/conf 2>/dev/null || :

###########################################
### simet-agent-lmap-tasks (lmap-tasks) ###

.PHONY: lmap-tasks-build lmap-tasks-install
# Build
lmap-tasks-build:
	$(MAKE) simet -C lmap-tasks

#Install
lmap-tasks-install: prepare lmap-tasks-build
	cp lmap-tasks/dist/bin/* dist/bin 2>/dev/null || :
	cp lmap-tasks/dist/conf/* dist/conf 2>/dev/null || :

######################
### twamp-client-c ###

.PHONY: twamp-client-c-build twamp-client-c-install
# Build
twamp-client-c-build:
	$(MAKE) simet -C twamp-client-c

# Install
twamp-client-c-install: prepare twamp-client-c-build
	cp twamp-client-c/dist/bin/* dist/bin/ 2>/dev/null || :

############################
### Git Subrepo commands ###
############################

# tcp-client-c
tcp-client-c-subrepo:
	git subrepo clone ssh://git@code.ceptro.br:7999/simet2/tcp-client-c.git tcp-client-c -b v0.1.0 -f

# twamp-client-c
twamp-client-c-subrepo:
	git submodule add --name twamp-client-c ssh://git@code.ceptro.br:7999/simet2/twamp-client-c.git twamp-client-c

# simet-agent-lmap-tasks (lmap-tasks)
lmap-tasks-subrepo:
	git subrepo clone ssh://git@code.ceptro.br:7999/simet2/simet-agent-lmap-tasks.git lmap-tasks -b v0.3.3 -f


####################
### DEV Commands ###
####################

# Dev and test commands for Alpine
dev:
	docker build environment/dev/ -t simet-agent-unix-img
	docker run \
		-it --rm \
		--name simet-agent-unix-dev \
		--mount type=bind,source="$(pwd)",target=/usr/simet-agent-unix \
	simet-agent-unix-img

dev-clean:
	-rm -rf dist

dev-install: dev-clean
	$(MAKE) tcp-client-c-install
	#$(MAKE) twamp-client-c-install
	#$(MAKE) lmap-tasks-install

### Features DEV Commands
# tcp-client-c for DEV
tcp-client-c-run:
	(./dist/bin/tcpc -c "http://docker.lab.simet.nic.br:8800/tcp-control" -h "docker.lab.simet.nic.br" -j "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM" 2> dist/bin/err.log)

# twamp-client-c for DEV
twamp-client-c-run:
	(./dist/bin/twampc -h "docker.lab.simet.nic.br")

# lmap-tasks for DEV
lmap-tasks-run:
	/bin/sh ./dist/bin/lmap_schedule_574.sh --config ./dist/conf/lmap_schedule_574.conf
