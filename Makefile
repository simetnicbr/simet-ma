# SIMET simet-agent-unix top-level Makefile
# Copyright (c) 2018 NIC.br
# Distributed under the GPLv2+

export PREFIX ?=/opt/simet
export SYSCONFDIR ?=$(PREFIX)/etc

export AGENT_VERSION :=$(shell cat version)

all: twamp-client-c.stamp simet-api.stamp

# twamp-client-c

twamp-client-c/configure: twamp-client-c/Makefile.am twamp-client-c/autogen.sh
	cd twamp-client-c ; ./autogen.sh

twamp-client-c/Makefile: twamp-client-c/configure
	cd twamp-client-c ; ./configure --prefix=$(PREFIX) --sysconfdir=$(SYSCONFDIR)

twamp-client-c.stamp: twamp-client-c/Makefile
	$(MAKE) -C twamp-client-c
	touch twamp-client-c.stamp

twamp-client-c-install: twamp-client-c.stamp
	$(MAKE) -C twamp-client-c install

twamp-client-c-clean:
	-$(MAKE) -C twamp-client-c clean
	-$(MAKE) -C twwap-client-c distclean || (cd twamp-client-c && rm -f config.status Makefile)
	rm -f twamp-client-c.stamp

# simet-api

simet-api.stamp:
	$(MAKE) -C simet-api && touch simet-api.stamp

simet-api-install: simet-api.stamp
	$(MAKE) -C simet-api install

simet-api-clean:
	$(MAKE) -C simet-api clean
	rm -f simet-api.stamp


install: twamp-client-c-install simet-api-install

clean: twamp-client-c-clean simet-api-clean

.PHONY: install clean
