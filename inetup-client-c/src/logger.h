#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>
#include <string.h>
#include <features.h>
#include <errno.h>

#define DEBUG_LOG(...) do {LOG_MESSAGE(stderr, "DEBUG"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define INFO_LOG(...) do {LOG_MESSAGE(stderr, "INFO"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define WARNING_LOG(...) do {LOG_MESSAGE(stderr, "WARNING"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define ERROR_LOG(...) do {LOG_MESSAGE(stderr, "ERROR"); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)
#define ERRNO_LOG(err, ...) do {LOG_MESSAGE(stderr, "ERROR"); fprintf(stderr, "(#%d %s) ", err, strerror(err)); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n");} while(0)

#define OUTPUT(...) do {fprintf(stdout, __VA_ARGS__);fprintf(stdout, "\n");}while(0)

#define LOG_MESSAGE(output, level) do {fprintf(stderr, "%s: {%s-%d}: ", level, __FILE__, __LINE__);} while(0)

#endif /* LOGGER_H_ */
