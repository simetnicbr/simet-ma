bin_PROGRAMS = twampc

twampc_SOURCES = logger.h \
				twamp.h twamp.c \
				message.h message.c \
				timestamp.h timestamp.c \
				report.h report.c \
				twampc.c
twampc_CFLAGS = -I .. -pthread -L json
twampc_LDFLAGS = @UBOX_LIBDIR@ -pthread -L json
twampc_LDADD = @LIB_UBOX@ ${JSON_LIBS}

#valgrind: twampc
#	valgrind --leak-check=full --track-origins=yes --xml-file=twampc_log.xml --xml=yes ./$(TWAMP_CLI)
#	valkyrie --view-log ./twampc_log.xml

#clean:
#	rm -f *.o
#	rm -f $(TWAMP_CLI)
#	rm -f twampc_log.xml
