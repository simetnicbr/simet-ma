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

simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet
EXTRA_DIST=
CLEANFILES=

if SIMETBOX_BUILD
dist_bin_SCRIPTS = simetbox_register_ma.sh
jsonfilter=jsonfilter
else
dist_bin_SCRIPTS = simet_register_ma.sh simet-ma_periodic.sh
jsonfilter=$(bindir)/jsonpath
endif

%.sh: %.sh.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" \
	    "$^" > "$@"

%.conf: %.conf.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g" \
	    -e "s!@JSONFILTER@!$(jsonfilter)!g" \
	    "$^" > "$@"

# _SCRIPT "sources" need to go in EXTRA_DIST, and the scripts themselves in CLEANFILES
EXTRA_DIST += simetbox_register_ma.sh.in simet_register_ma.sh.in simet-ma_periodic.sh.in
CLEANFILES += $(dist_bin_SCRIPTS)

# Ensures the empty directories we don't create at runtime do exist
install-data-local:
	$(MKDIR_P) -m 0700 -- "$(DESTDIR)$(simetconfdir)"

dist_simetlib_DATA  = conf/simet-ma.conf agent-version.txt
EXTRA_DIST += conf/simet-ma.conf.in
CLEANFILES += $(dist_simetlib_DATA)

# Other non-source files we want in the source tarball
EXTRA_DIST += API.md

agent-version.txt:
	echo $(PACKAGE)/$(PACKAGE_VERSION) > "$@" && chmod 0644 "$@"
