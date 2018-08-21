#ifndef TWAMP_H_
#define TWAMP_H_

#include "report.h"

#ifdef  HAVE_JSON_C_JSON_H  
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H   
#include <json/json.h>
#elif HAVE_JSON_H
#include <json.h>  
#endif

/* TWAMP parameters struct */
typedef struct twamp_parameters {
    char *device_id;
    char *host;
    char *port;
    int family;
    int timeout_test;
    unsigned int packets_count;
    unsigned int packets_interval_ns;
} TWAMPParameters;

typedef struct twamp_test_parameters {
    int test_socket;
    TWAMPParameters param;
    TWAMPReport * report;
} TestParameters;

int twamp_run_client(TWAMPParameters param);

#endif /* TWAMP_H_ */