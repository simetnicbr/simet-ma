# SIMET simet-agent-unix top-level Makefile
# Copyright (c) 2018 NIC.br
# Distributed under the GPLv2+

PREFIX ?=/opt/simet
SYSCONFDIR ?= $(PREFIX)/etc

all: twamp-client-c.stamp simet-common.stamp

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

# simet-common

simet-common.stamp:
	$(MAKE) -C simet-common && touch simet-common.stamp

simet-common-install: simet-common.stamp
	$(MAKE) -C simet-common install

simet-common-clean:
	$(MAKE) -C simet-common clean
	rm -f simet-common.stamp


install: twamp-client-c-install simet-common-install

clean: twamp-client-c-clean simet-common-clean

.PHONY: install clean
