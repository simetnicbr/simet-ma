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

%.sh: %.sh.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g"  "$^" > "$@"

%.conf: %.conf.in
	sed -e "s!@SIMETCONFDIR@!$(simetconfdir)!g" -e "s!@SIMETLIBDIR@!$(simetlibdir)!g" \
	    -e "s!@BINDIR@!$(bindir)!g" -e "s!@LOCALSTATEDIR@!$(localstatedir)!g"  "$^" > "$@"

if SIMETBOX_BUILD
dist_bin_SCRIPTS = simetbox_register_ma.sh
else
dist_bin_SCRIPTS = simet_register_ma.sh
endif

create-dirs:
	[ -d "$(DESTDIR)$(simetconfdir)" ] || mkdir -m 0700 -p "$(DESTDIR)$(simetconfdir)"

install-exec-hook: create-dirs
install-data-hook: create-dirs

dist_simetlib_DATA  = conf/simet-ma.conf agent-version.txt

CLEANFILES = $(dist_simetlib_DATA) $(dist_bin_SCRIPTS)

agent-version.txt:
	echo $(PACKAGE)/$(PACKAGE_VERSION) > "$@" && chmod 0644 "$@"
