#include "tcpc_config.h"
#include "report.h"

#include "json-c/json.h"
#include <stdio.h>

void add_uint64_as_string(json_object * jobj, char * name, uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIu64, value);

    json_object * jbuf = json_object_new_string(buf);

    json_object_object_add(jobj,name, jbuf);
}

json_object * createReport(json_object* jresults, DownResult * downloadRes, uint32_t counter) {

    json_object * jtable = json_object_new_object();
    
    json_object * jfuncarray = json_object_new_array();
    json_object * jfunc = json_object_new_object();
    json_object_object_add(jfunc,"uri", json_object_new_string("TWThroughput_Active_TCP-Periodic_Multiple_Raw_V1"));
    json_object_object_add(jfunc, "role", json_object_new_string("client"));
    json_object_array_add(jfuncarray, jfunc);
    json_object_object_add(jtable,"function", jfuncarray);

    json_object * jcolumn = json_object_new_array();
    json_object_array_add(jcolumn, json_object_new_string("sequence"));
    json_object_array_add(jcolumn, json_object_new_string("bits"));
    json_object_array_add(jcolumn, json_object_new_string("intervalMs"));
    json_object_array_add(jcolumn, json_object_new_string("direction"));
    json_object_object_add(jtable,"column", jcolumn);

    for(int i=0; i<counter; i++) {
        json_object * jpacket = json_object_new_object();

        add_uint64_as_string(jpacket, "sequence", (uint64_t)downloadRes[i].sequence);
        add_uint64_as_string(jpacket, "bits", downloadRes[i].bits);
        add_uint64_as_string(jpacket, "intervalMs", downloadRes[i].intervalMs);
        json_object_object_add(jpacket, "direction", json_object_new_string("download"));

        json_object_array_add(jresults, jpacket);
    }
    json_object_object_add(jtable,"row", jresults);

    return jtable;
}
