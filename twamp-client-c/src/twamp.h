/*
 * SIMET2 MA - TWAMP client
 * Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.  In every case, additional
 * restrictions and permissions apply, refer to the COPYING file in the
 * program Source for details.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License and the COPYING file in the program Source
 * for details.
 */

#ifndef TWAMP_H_
#define TWAMP_H_

#include "report.h"
#include <assert.h>
#include <stdio.h>

#ifdef  HAVE_JSON_C_JSON_H
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H
#include <json/json.h>
#elif HAVE_JSON_H
#include <json.h>
#endif

#define TWAMP_DEFAULT_PORT "862"

#define SIMET_TWAMP_AUTH_MINKEYSIZE 16
#define SIMET_TWAMP_AUTH_MAXKEYSIZE 64

#define SIMET_TWAMP_IDCOOKIE_V1LEN 16
#define SIMET_TWAMP_IDCOOKIE_V1SIG 0x83b8c493

struct __attribute__((__packed__)) simet_cookie {
    /* SIMET cookie v1 */
    uint32_t sig; /* SIMET_TWAMP_IDCOOKIE_V1SIG, network byte order */
    uint8_t data[SIMET_TWAMP_IDCOOKIE_V1LEN]; /* SID from Accept-TW-Session */
};

#define SIMET_STAMP_AUTHTLV_TYPE    252
#define SIMET_STAMP_TLV_PEN         60267    /* IANA-assigned Private Enterprise Number, CEPTRO.br */
#define SIMET_STAMP_TLV_AUTHCOOKIE  0x0100   /* simet_tlv_sub_type */

struct __attribute__((__packed__)) stamp_tlv_header {
    uint8_t  flags;
    uint8_t  type;
    uint16_t length; /* Network byte order */
};

struct __attribute__((__packed__)) stamp_private_tlv {
    struct   stamp_tlv_header hdr; /* hdr.type must be 252, 253 or 254 */
    uint32_t private_enterprise_number; /* Network byte order */
    uint16_t simet_tlv_sub_type;        /* Network byte order */
    uint8_t  data[]; /* data[hdr.length - 8] */
};

enum {
    TWAMP_MODE_TWAMP = 0,
    TWAMP_MODE_TWAMPLIGHT,
};

/* TWAMP authentication key */
typedef struct twamp_key {
    uint8_t data[SIMET_TWAMP_AUTH_MAXKEYSIZE];
    size_t  len; /* 0 for no key */
} TWAMPKey;

enum report_mode {
    TWAMP_REPORT_MODE_FRAGMENT = 0, /* Array contents */
    TWAMP_REPORT_MODE_OBJECT   = 1, /* array or object */
    TWAMP_REPORT_MODE_NONE     = 2, /* No report */
    TWAMP_REPORT_MODE_EOL
};

/* TWAMP parameters struct */
/* all pointers are *not* owned by the struct */
typedef struct twamp_parameters {
    const char * const host;
    const char * const port;
    const struct sockaddr_storage * const source_ss;
    sa_family_t family;
    int connect_timeout;

    enum report_mode lmap_report_mode;
    const char *lmap_report_path;  /* when not NULL, causes fopen/reopen of lmap_report_output */
    FILE *lmap_report_output;      /* will be used if non-NULL and lmap_report_path is NULL */

    int summary_report_enabled;
    const char *summary_report_path;  /* when not NULL, causes fopen/reopen of summary_report_output */
    FILE *summary_report_output;      /* will be used if non-NULL and summary_report_path is NULL */

    unsigned int packets_count;
    unsigned int payload_size;
    unsigned int packets_max;
    unsigned int packets_interval_us;
    unsigned int packets_timeout_us;
    unsigned int ttl;
    TWAMPKey key;
} TWAMPParameters;

/* Context */
/* Pointers are *not* owned by this struct */
typedef struct twamp_test_context {
    volatile int abort_test; /* NZ = stop test */
    int test_socket;
    struct timespec clock_offset;
    int cookie_enabled;
    struct simet_cookie cookie;
    TWAMPParameters param;
    TWAMPReport * report;
} TWAMPContext;

int twamp_run_client(TWAMPParameters * const param);
int twamp_run_light_client(TWAMPParameters * const param);

TWAMPReport * twamp_report_init(const sa_family_t family, const char * const host);
void twamp_report_done(TWAMPReport *);

int twamp_report_testsession_connection(TWAMPReport *, int sockfd);
int twamp_report_statistics(TWAMPReport *report, TWAMPParameters *param);
int twamp_report_render_lmap(TWAMPReport*, TWAMPParameters*);
int twamp_report_render_summary(TWAMPReport *report, TWAMPParameters *param);

#endif /* TWAMP_H_ */
