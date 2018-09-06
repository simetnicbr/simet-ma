bin_PROGRAMS = twampc

twampc_SOURCES = libubox/usock.h libubox/usock.c \
		 logger.h \
				twamp.h twamp.c \
				message.h message.c \
				timestamp.h timestamp.c \
				report.h report.c \
				twampc.c
twampc_CFLAGS = -I .. -pthread -L json
twampc_LDFLAGS = -pthread -L json
twampc_LDADD = ${JSON_LIBS}

#valgrind: twampc
#	valgrind --leak-check=full --track-origins=yes --xml-file=twampc_log.xml --xml=yes ./$(TWAMP_CLI)
#	valkyrie --view-log ./twampc_log.xml

#clean:
#	rm -f *.o
#	rm -f $(TWAMP_CLI)
#	rm -f twampc_log.xml
