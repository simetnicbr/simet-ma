all: build

pwd=$(shell pwd)

### Build command
build:
	$(MAKE) tcp-client-c-build

### Features

# tcp-client-c
tcp-client-c-subtree:
	git subtree add --prefix tcp-client-c ssh://git@code.ceptro.br:7999/simet2/tcp-client-c.git tags/v0.1.0 --squash

tcp-client-c-build:
	$(MAKE) simet -C tcp-client-c

### Dev and test commands for Alpine
dev:
	docker build environment/dev/ -t simet-agent-unix-img
	docker run \
		-it --rm \
		--name simet-agent-unix-dev \
		--mount type=bind,source="$(pwd)",target=/usr/simet-agent-unix \
	simet-agent-unix-img

dev-clean:
	-rm -rf bin
	-rm -rf conf

dev-install:
	-mkdir bin
	-mkdir conf
	$(MAKE) tcp-client-c-install

# tcp-client-c for DEV
tcp-client-c-install:
	-cp tcp-client-c/dist/bin/* bin 2>/dev/null || :
	-cp tcp-client-c/dist/conf/* conf 2>/dev/null || :

tcp-client-c-run:
	(./bin/tcpc -c "http://docker.lab.simet.nic.br:8800/tcp-control" -h "docker.lab.simet.nic.br" -j "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM" 2> bin/err.log)