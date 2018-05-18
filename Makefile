all: simet

pwd = $(shell pwd)

### BUILD command
build:
	(cd tcp-src && make tcpc)

### SIMET command
simet: build
	#mkdir -pv dist/{bin,conf}
	mkdir -p dist/bin
	mkdir -p dist/conf
	(cp tcp-src/tcpc dist/bin/tcpc)

### DEV commands
dev:
	docker build environment/alpine/. -t tcpc-c-devel
	docker run \
		-it --rm --name tcpc-c-dev \
		--mount type=bind,source="$(pwd)",target=/c/code.ceptro.br/simet2/tcp-client-c \
		tcpc-c-devel

network-localhost:
	-docker network connect kong-net tcpc-c-dev
	-docker network connect kong-net tcp-go-dev

run: build
	(cd tcp-src; ./tcpc -c "http://kong:8000/tcp-control" -h "tcp-go-dev" 2> err.log)

run-lab: build
	(cd tcp-src; ./tcpc -c "http://docker.lab.simet.nic.br:8800/tcp-control" -h "docker.lab.simet.nic.br" -j "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM" 2> err.log)

clean:
	-(cd tcp-src; rm *.o)
	-(cd tcp-src; rm tcpc)
	-(cd tcp-src; rm err.log)
	-(rm -rf dist)

build-image:
	docker build . -t tcpc-img

run-image:
	docker run \
		-it --rm --name tcpc-c \
		tcpc-img