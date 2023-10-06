// Name: Shibo Wang
// Case ID: sxw1127
// Filename: Proj2.c
// Description: This file included only the main function of the whole project, all the functions are called here

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socket_methods.h"

int main(int argc, char *argv[]) {
    /* define the value in main function */
    struct sockaddr_in sin;
    struct hostent *hinfo;
    struct protoent *protoinfo;
    struct Opts opt;
    int sd;
    int if_run = TRUE;
    char *request;
    char *response;

    /* initialize the options opt */
    parseargs(&opt, argc, argv);

    /* judge whether the MUST-CONTAIN options is presented, if not show how to use the program */
    if (!opt.u_flag || !opt.o_flag)
        usage(argv[PROJECT_POSITION]);

    /* start debug mode */
    debug_mode(&opt);

    /* if_run is set to TRUE at the beginning so the following parts will be run at least once */
    while (if_run) {
        /* lookup the hostname */
        hinfo = gethostbyname(opt.hostname);
        if (hinfo == NULL)
            errexit("cannot find hostname: %s", opt.hostname);

        /* set endpoint information */
        memset((char *) &sin, 0x0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(DEFAULT_PORT);
        memcpy((char *) &sin.sin_addr, hinfo->h_addr, hinfo->h_length);

        /* get the protocol */
        if ((protoinfo = getprotobyname(PROTOCOL)) == NULL)
            errexit("cannot find protocol information for %s", PROTOCOL);

        /* allocate a socket */
        sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
        if (sd < BOUND)
            errexit("cannot create socket", NULL);

        /* connect the socket */
        if (connect(sd, (struct sockaddr *) &sin, sizeof(sin)) < BOUND)
            errexit("cannot connect", NULL);

        /* start the request, it will return the request content */
        request = request_mode(&opt);

        /* send the request */
        if (send(sd, request, strlen(request), DEFAULT_SEND) < BOUND) {
            errexit("request failed", NULL);
        }

        /* decode the response from the socket, use chunked decoding method if necessary */
        response = socket_decode(sd);
        if (opt.C_flag) {
            response = decode_chunk(response);
        }

        /* start response mode */
        response_mode(&opt, response);
        write_file(&opt, response);
        if_run = opt.f_flag;
        close(sd);
        free(response);
        free(request);
    }

    /* close & exit */
    cleanupStruct(&opt);
    exit(0);
}
