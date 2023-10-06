// Name: Shibo Wang
// Case ID: sxw1127
// Filename: socket_methods.h
// Description: Header file of all the functions called in main

#ifndef PROJECT2_SOCKET_METHODS_H
#define PROJECT2_SOCKET_METHODS_H

#define TRUE 1
#define FALSE 0
#define ERROR_READ (-1)
#define ERROR 1
#define MIN_ARGC 1
#define SKIP_PROTOCOL 3
#define END_POSITION 1
#define DEFAULT_PATH 2
#define DEFAULT_PORT 80
#define PROTOCOL "tcp"
#define BUFLEN 2048
#define BUF_EXTEND 2048
#define INITIAL_ARGV 1
#define INITIAL_BYTE 0
#define COMPLETE_READ 0
#define HTTP_REQUEST_LEN 100
#define HEADER_END 4
#define MIN_URL_LEN 5
#define PROJECT_POSITION 0
#define BOUND 0
#define DEFAULT_SEND 0
#define HEX_BASE 16
#define OPTION_END (-1)
#define CHUNK_END 2
#define LOCATION_LEN 10
#define BYTE_LEN 1

/*Structure containing the options get from command line.*/
struct Opts {
    int u_flag;
    int o_flag;
    int d_flag;
    int q_flag;
    int r_flag;
    int f_flag;
    int C_flag;
    char *hostname;
    char *path;
    char *filename;
};

void errexit(char *format, char *arg);

void usage(char *program_name);

int hex_to_decimal(const char *hex);

void extract_hostname_path(char *url, struct Opts *opts);

void cleanupStruct(struct Opts *opts);

void check_protocol(char *URL);

void parseargs(struct Opts *opts, int argc, char *argv[]);

void debug_mode(struct Opts *opts);

char *request_mode(struct Opts *opts);

char *socket_decode(int socket);

char *decode_chunk(char *response);

void response_mode(struct Opts *opts, char *Buffer);

void write_file(struct Opts *opts, const char *Buffer);

#endif //PROJECT2_SOCKET_METHODS_H
