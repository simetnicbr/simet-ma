simetconfdir=$(sysconfdir)/simet
simetlibdir=$(libdir)/simet

if SIMETBOX_BUILD
dist_bin_SCRIPTS = simetbox_register_ma.sh
else
dist_bin_SCRIPTS = simet_register_ma.sh
endif

dist_simetconf_DATA = conf/*
dist_simetlib_DATA  = agent-version.txt

CLEANFILES = agent-version.txt

agent-version.txt:
	echo $(PACKAGE)/$(PACKAGE_VERSION) > "$@" && chmod 0644 "$@"
