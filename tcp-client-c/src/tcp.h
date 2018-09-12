#ifndef TCP_H_
#define TCP_H_

#include <sys/types.h>

/* TCP measure context struct */
typedef struct measure_context {
    char *agent_id;
    char *host_name;
    char *control_url;
    char *port;
    char *token;
    int family;
    unsigned int timeout_test;
    unsigned int numstreams;
    unsigned int test_duration;
} MeasureContext;

struct MemoryStruct {
    char *memory;
    size_t size;
};

int tcp_client_run(MeasureContext);

#endif /* TCP_H_ */
