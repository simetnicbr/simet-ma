bin_PROGRAMS = simet_dnsaddr

simet_dnsaddr_SOURCES = base64.h base64.c \
		retry.h timespec.h simet_err.h logger.h \
		report.h report.c \
		simet_random.h simet_random.c \
		simet_dnsaddr.c

simet_dnsaddr_LDADD = ${JSON_LIBS}

# "make check" and run manually for now
check_PROGRAMS = base64_test
base64_test_SOURCES = base64.h base64.c base64_test.c
