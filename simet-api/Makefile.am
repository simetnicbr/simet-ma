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
