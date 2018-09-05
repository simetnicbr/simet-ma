#ifndef REPORT_H_
#define REPORT_H_

#include "json-c/json.h"

typedef struct tcp_download_result {
    uint32_t sequence;
    uint64_t bits;
    uint64_t intervalMs;
} DownResult;

json_object * createReport(json_object*, DownResult*, uint32_t); 

#endif /* REPORT_H_ */
