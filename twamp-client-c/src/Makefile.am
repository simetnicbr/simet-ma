## Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
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

bin_PROGRAMS = twampc

twampc_SOURCES = libubox/usock.h libubox/usock.c \
		 logger.h simet_err.h \
				twamp.h twamp.c \
				base64.h base64.c \
				message.h message.c \
				timestamp.h timestamp.c \
				report.h report.c \
				twampc.c
twampc_CFLAGS = -I .. -pthread -L json
twampc_LDFLAGS = -pthread -L json
twampc_LDADD = ${JSON_LIBS}

check_PROGRAMS = base64_test
base64_test_SOURCES = base64.h base64.c base64_test.c

#valgrind: twampc
#	valgrind --leak-check=full --track-origins=yes --xml-file=twampc_log.xml --xml=yes ./$(TWAMP_CLI)
#	valkyrie --view-log ./twampc_log.xml

#clean:
#	rm -f *.o
#	rm -f $(TWAMP_CLI)
#	rm -f twampc_log.xml
