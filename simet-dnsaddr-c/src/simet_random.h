/*
 * SIMET2 MA - urandom access
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

#include <stddef.h>

#define SIMET_RANDOM_SOURCE "/dev/urandom"

/*
 * Fills buf with random data from getrandom() or SIMET_RANDOM_SOURCE,
 * returns 0 if sucessfull, -1 with errno set otherwise
 */
int simet_getrandom(void * const buf, size_t buf_len);

/* vim: set et ts=8 sw=4 : */
