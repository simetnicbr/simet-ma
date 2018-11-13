## Copyright (c) 2018 NIC.br <medicoes@simet.nic.br>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.  In every case, additional
## restrictions and permissions apply, refer to the COPYING file in the
## program Source for details.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License and the COPYING file in the program Source
## for details.

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

