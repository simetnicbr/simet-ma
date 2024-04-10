/*
 * SIMET2 MA SIMET Spoofer client (sspooferc) - reports
 * Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>
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

#ifndef REPORT_H_
#define REPORT_H_

#include "sspooferc_config.h"

#include <inttypes.h>

enum report_mode {
    SSPOOF_REPORT_MODE_FRAGMENT = 0, /* Array contents */
    SSPOOF_REPORT_MODE_OBJECT   = 1, /* array or object */
    SSPOOF_REPORT_MODE_EOL
};

int sspoof_render_report(struct sspoof_server ** svec, unsigned int nvec, enum report_mode report_mode);

#endif /* REPORT_H_ */
