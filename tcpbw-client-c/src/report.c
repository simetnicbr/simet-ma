/*
 * Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tcpbwc_config.h"
#include "report.h"

#include "logger.h"

#include "json-c/json.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

static void xx_json_object_array_add_uin64_as_str(json_object *j, uint64_t v)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%" PRIu64, v);
    json_object_array_add(j, json_object_new_string(buf));
}

/**
 * createReport - create the JSON LMAP-like report snippet
 *
 * if @jresults is not NULL, include it (upload direction measurement results).
 * Then, render the rows for DownResult[] (download direction measurement results), if any.
 *
 * @jresults MUST use the same column ordering as we do:
 * sequence; bits; streams; interval (ms); direction
 */
json_object *createReport(json_object *jresults, DownResult *downloadRes, uint32_t counter)
{
    assert(downloadRes);
    /* FIXME: handle NULL returns as error... */

    json_object *jo, *jo1; /* used when transfering ownership via _add */

    /* shall contain function, column, row arrays */
    json_object *jtable = json_object_new_object();
    assert(jtable);

    if (!json_object_is_type(jresults, json_type_array))
    {
        WARNING_LOG("Received unusable data from server, ignoring...");
        jresults = NULL;
    }

    /* function object list */
    jo = json_object_new_array();
    jo1 = json_object_new_object();
    assert(jo && jo1);
    json_object_object_add(jo1, "uri", json_object_new_string("TWThroughput_Active_TCP-Periodic_Multiple_Raw_V1"));
    json_object_object_add(jo1, "role", json_object_new_string("client"));
    json_object_array_add(jo, jo1);
    json_object_object_add(jtable, "function", jo);
    jo = jo1 = NULL;

    /* columns list */
    jo = json_object_new_array();
    assert(jo);
    json_object_array_add(jo, json_object_new_string("sequence"));
    json_object_array_add(jo, json_object_new_string("bits"));
    json_object_array_add(jo, json_object_new_string("streams"));
    json_object_array_add(jo, json_object_new_string("intervalMs"));
    json_object_array_add(jo, json_object_new_string("direction"));
    json_object_object_add(jtable, "column", jo);
    jo = NULL;

    /* rows (result data) */
    json_object *jrows = (jresults) ? jresults : json_object_new_array();
    assert(jrows);

    for (unsigned int i = 0; i < counter; i++)
    {
        json_object *jrow = json_object_new_array();
        assert(jrow);

        /* WARNING: keep the same order as in the columns list! */
        xx_json_object_array_add_uin64_as_str(jrow, i + 1);
        xx_json_object_array_add_uin64_as_str(jrow, downloadRes[i].bytes * 8U);
        xx_json_object_array_add_uin64_as_str(jrow, downloadRes[i].nstreams);
        xx_json_object_array_add_uin64_as_str(jrow, (uint64_t)downloadRes[i].interval / 1000UL);
        json_object_array_add(jrow, json_object_new_string("download"));

        /* add row to list of rows */
        jo = json_object_new_object();
        json_object_object_add(jo, "value", jrow);
        json_object_array_add(jrows, jo);
        jo = NULL;
    }

    json_object_object_add(jtable, "row", jrows);
    jrows = NULL;

    return jtable;
}
