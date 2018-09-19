##
## Toplevel Makefile.am for tcpbwc - SIMET2 MA TCP bandwidth test client
## Copyright (c) 2018 NIC.br
##

SUBDIRS = src

EXTRA_DIST	= autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version
