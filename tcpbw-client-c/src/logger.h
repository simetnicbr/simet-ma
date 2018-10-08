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

#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>
#include <string.h>
#include <features.h>
#include <errno.h>

#define DEBUG_LOG(...) do {LOG_MESSAGE(stderr, "DEBUG"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define INFO_LOG(...) do {LOG_MESSAGE(stderr, "INFO"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define WARNING_LOG(...) do {LOG_MESSAGE(stderr, "WARNING"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define ERROR_LOG(err, ...) do {LOG_MESSAGE(stderr, "ERROR"); fprintf(stderr, "(#%d %s) ", err, strerror(err)); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define ERRNO_LOG(...) do {LOG_MESSAGE(stderr, "ERRNO"); fprintf(stderr, "(#%d %s) ", errno, strerror(errno)); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)

#define OUTPUT(...) do {fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}while(0)

#define LOG_MESSAGE(output, level) do {fprintf(stderr, "%s %s [%s] {%s-%d}: ", __DATE__, __TIME__, level, __FILE__, __LINE__);} while(0)

#endif /* LOGGER_H_ */
