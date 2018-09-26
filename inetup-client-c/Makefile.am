##
## Toplevel Makefile.am for inetupc - SIMET2 MA Internet network availability (client)
## Copyright (c) 2018 NIC.br
##

SUBDIRS = src

EXTRA_DIST = autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version
