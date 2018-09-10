##
## Toplevel Makefile.am for twampc
## Copyright (c) 2017 NIC.br
##

SUBDIRS = src

EXTRA_DIST	= autogen.sh version version.sh

dist-local: version

version: $(top_srcdir)/version.sh
	$(top_srcdir)/version.sh > version
