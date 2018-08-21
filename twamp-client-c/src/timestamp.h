#ifndef NTP_TIMESTAMP_H_
#define NTP_TIMESTAMP_H_

#include <inttypes.h>

#include <sys/types.h>

/* Timestamp is NTP time (RFC1305).
 * Should be in network byte order!      */
typedef struct ntp_timestamp {
    uint32_t integer;
    uint32_t fractional;
} Timestamp;

/***********/
/* HELPERS */
/***********/

// timeval_to_timestamp converts struct timeval to Timestamp
Timestamp timeval_to_timestamp(const struct timeval *tv);

// timestamp_to_timeval converts Timestamp to struct timeval
struct timeval timestamp_to_timeval(const Timestamp *ts);

// encode_be_timestamp converts Timestamp to Big Endian (Network)
void encode_be_timestamp(Timestamp *ts);

// decode_be_timestamp converts Big Endian (Network) to local Endian
void decode_be_timestamp(Timestamp *ts);

uint64_t timeval_to_microsec(const struct timeval *tv);

#endif /* NTP_TIMESTAMP_H_ */