bin_PROGRAMS = tcpc

tcpc_SOURCES = libubox/usock.h libubox/usock.c\
	        tcpc.h \
		logger.h \
		report.h report.c \
		tcpc-tcp.c tcpc.c

tcpc_CPPFLAGS = @LIBCURL_CPPFLAGS@
tcpc_CFLAGS = -I .. -pthread -L json
tcpc_LDFLAGS = -pthread -L json
tcpc_LDADD = ${JSON_LIBS} @LIBCURL@

