bin_PROGRAMS = tcpc

tcpc_SOURCES = tcp.h \
		logger.h \
		report.h report.c \
		tcp.c tcpc.c

tcpc_CPPFLAGS = @LIBCURL_CPPFLAGS@
tcpc_CFLAGS = -I .. -pthread -L json
tcpc_LDFLAGS = @UBOX_LIBDIR@ -pthread -L json
tcpc_LDADD = @LIB_UBOX@ ${JSON_LIBS} @LIBCURL@

