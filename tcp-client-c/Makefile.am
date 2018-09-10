##
## Toplevel Makefile.am for tcpc
## Copyright (c) 2018 NIC.br
##

SUBDIRS = src

EXTRA_DIST	= autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version
