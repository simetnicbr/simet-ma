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

dev-install:
	mkdir bin
	mkdir conf
	cp tcp-client-c/bin/* bin
	cp tcp-client-c/conf/* conf