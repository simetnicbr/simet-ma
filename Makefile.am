##
## Toplevel Makefile.am for simet-ma
## Copyright (c) 2018 NIC.br
##
## License: GPLv2+

SUBDIRS     = simet-api twamp-client-c tcp-client-c simet-runner
EXTRA_DIST  = autogen.sh version version.sh

version:
	$(top_srcdir)/version.sh > version

.PHONY: bump-version
bump-version:
	-rm -f version
	$(top_srcdir)/version.sh > version

dist-local: version
