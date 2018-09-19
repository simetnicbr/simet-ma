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
    char *sessionid;
    int family;
    unsigned int timeout_test;
    unsigned int numstreams;
    unsigned int test_duration;
    unsigned int sample_period_ms;
} MeasureContext;

struct MemoryStruct {
    char *memory;
    size_t used;
    size_t allocated;
};

int tcp_client_run(MeasureContext);

#define MAX_CONCURRENT_SESSIONS 10U

#endif /* TCP_H_ */
