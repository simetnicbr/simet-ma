#ifndef REPORT_H_
#define REPORT_H_

#include "json-c/json.h"

typedef struct tcp_download_result {
    uint64_t bytes;
    uint64_t interval; /* microseconds */
    unsigned int nstreams;
} DownResult;

json_object * createReport(json_object*, DownResult*, uint32_t); 

#endif /* REPORT_H_ */
