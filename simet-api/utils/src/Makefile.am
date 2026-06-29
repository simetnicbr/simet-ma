bin_PROGRAMS = simet_gen_vlabel simet_hash

simet_gen_vlabel_SOURCES = crc16.h crc16.c \
			   sha256.h sha256.c \
			   base64.h base64.c \
			   simet_gen_vlabel.c

simet_hash_SOURCES =	   sha256.h sha256.c \
			   base64.h base64.c \
			   simet_hash.c

# "make check" and run manually for now
check_PROGRAMS = base64_test
base64_test_SOURCES = base64.h base64.c base64_test.c
