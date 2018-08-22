PERFIX ?=/usr
LIBDIR ?=$(PREFIX)/lib
SYSCONFDIR ?=$(PREFIX)/etc

ifndef AGENT_VERSION
$(error AGENT_VERSION makefile/enviroment variable undefined)
endif

all:

clean:

install:
	install -m 0755 -d "$(DESTDIR)$(SYSCONFDIR)/simet"
	install -m 0644 conf/* "$(DESTDIR)$(SYSCONFDIR)/simet/"
	install -m 0755 -d "$(DESTDIR)$(LIBDIR)/simet"
	echo $(AGENT_VERSION) > "$(DESTDIR)$(LIBDIR)/simet/agent-version.txt"

.PHONY: clean
