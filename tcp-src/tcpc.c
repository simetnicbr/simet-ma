/* Simple TCP Client */
#include "tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char **argv) {

    char *device_id = "device_id";
    char *host_name = "docker.lab.simet.nic.br";
    char *control_url = "http://docker.lab.simet.nic.br:8800/tcp-control";
    char *token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJUY3BEb3dubG9hZE1lYXN1cmUiLCJleHAiOjE5MjA2MTY3OTMsImlzcyI6InNpbWV0Lm5pYy5iciIsIm1lYXN1cmVfdHlwZSI6Imh0dHBzRG93bmxvYWQifQ.XXGglVdL6Qb2VYi62hf94X--UsxTXMB0elNzRl2_XKM";
    char *port = "20000";
    int family = 4;
    int timeout_test = 30;

    int option;

    while ((option = getopt (argc, argv, "c:h:f:p:t:d:j:")) != -1) {
        switch (option) {
            case 'c':
                control_url = optarg;
                break;
            case 'h':
                host_name = optarg;
                break;
            case 'f':
                family = atoi(optarg);
                break;
            case 'p':
                port = optarg;
                break;
            case 't':
                timeout_test = atoi(optarg);
                break;
            case 'd':
                device_id = optarg;
                break;
            case 'j':
                token = optarg;
                break;
            case '?':
                fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
                return 1;
        }
    };

    MeasureContext ctx;
    ctx.device_id = device_id;
    ctx.host_name = host_name;
    ctx.control_url = control_url;
    ctx.port = port;
    ctx.token = token;
    ctx.family = family;
    ctx.timeout_test = (timeout_test <= 0 || timeout_test > 40) ? 40 : timeout_test;

    int value = tcp_client_run(ctx);

    if (value != 0) {
        fprintf(stderr, "TCP CLIENT RUN ERROR\n");
    }

    return 0;
}
