TCPC-C=tcp-client-c

DEPS = \
	tcp.h \
	report.h \

OBJ = \
	tcp.o \
	report.o \
	tcpc.o \

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

tcpc: $(OBJ)
	$(CC) -Wall -o $@ $^ $(CFLAGS) -lcurl -lubox -ljson-c