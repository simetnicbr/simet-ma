#ifndef TCP_H_
#define TCP_H_

#include <sys/types.h>

/* TCP measure context struct */
typedef struct measure_context {
    char *device_id;
    char *host_name;
    char *control_url;
    char *port;
    char *token;
    int family;
    int timeout_test;
} MeasureContext;

struct MemoryStruct {
    char *memory;
    size_t size;
};

int tcp_client_run(MeasureContext);

#endif /* TCP_H_ */