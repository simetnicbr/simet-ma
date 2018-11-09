##
## Toplevel Makefile.am for simet-ma
## Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
##
## This program is free software: you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation, either version 3 of the
## License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS     = simet-api twamp-client-c tcpbw-client-c inetup-client-c simet-runner cmake-projects
EXTRA_DIST  = autogen.sh version version.sh

# we need to use an intermetiate variable, otherwise the shell dirties the
# repository creating the output file *before* running the version.sh script
version:
	VER=$$( $(top_srcdir)/version.sh ) && echo "$${VER}" > version

dist-local: version

# Creates a tarball of binaries, akin to how "make dist" creates a source distribution tarball
bin-dist: all
	test -d "$(abs_top_builddir)"
	-rm -rf "$(abs_top_builddir)/binary-dist"
	$(MKDIR_P) -- "$(abs_top_builddir)/binary-dist"
	$(MAKE) install-strip DESTDIR="$(abs_top_builddir)/binary-dist"
	tar zcf "${PACKAGE}-${VERSION}.binaries.tar.gz" --owner=root --group=root -C "$(abs_top_builddir)/binary-dist" .
	rm -rf "$(abs_top_builddir)/binary-dist"

# SIMET internal: reminder of how to update the version file
.PHONY: bump-version
bump-version:
	-rm -f version
	$(top_srcdir)/version.sh > version
	-debchange -p --noquery -v "$(shell cat $(top_srcdir)/version | sed -e 's/^v//' -e 's/-/+/g' -e 's/+$$//')" -m "New release"
