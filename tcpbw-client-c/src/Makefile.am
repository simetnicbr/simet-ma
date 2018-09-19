bin_PROGRAMS = tcpbwc

tcpbwc_SOURCES = libubox/usock.h libubox/usock.c\
	        tcpbwc.h \
		logger.h \
		report.h report.c \
		tcpbwc-tcp.c tcpbwc.c

tcpbwc_CPPFLAGS = @LIBCURL_CPPFLAGS@
tcpbwc_CFLAGS = -I .. -pthread -L json
tcpbwc_LDFLAGS = -pthread -L json
tcpbwc_LDADD = ${JSON_LIBS} @LIBCURL@

