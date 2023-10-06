// Name: Shibo Wang
// Case ID: sxw1127
// Filename: socket_methods.c
// Description: Source file of all the funcitons called in main

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "socket_methods.h"

/* global value */
int ALL_valid = TRUE;
int IF_write = FALSE;
size_t bytes_read = INITIAL_BYTE;

/* if the input arguments is INVALID, show the way to specify each option and the function of each option */
void usage(char *program_name) {
    fprintf(stderr, "%s -u <URL> [-d] [-q] [-r] -o <filename>\n", program_name);
    fprintf(stderr, "   -u <URL>        MUST CONTAIN: input the <URL> to the program\n");
    fprintf(stderr, "   -o <filename>   MUST CONTAIN: output the content to the <filename>\n");
    fprintf(stderr, "   -d              Optional:     start debug mode\n");
    fprintf(stderr, "   -q              Optional:     start request mode\n");
    fprintf(stderr, "   -r              Optional:     start response mode\n");
    fprintf(stderr, "   -C              Optional:     use http 1.1\n");
    exit(ERROR);
}

/* when the host name is INVALID, throw an error to show the host cannot be found */
void errexit(char *format, char *arg) {
    fprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    exit(ERROR);
}

/* change hex into decimal */
int hex_to_decimal(const char *hex) {
    int result = (int) strtol(hex, NULL, HEX_BASE);
    return result;
}

/* extract hostname and path from URL */
void extract_hostname_path(char *url, struct Opts *opts) {
    check_protocol(url);
    size_t maxLen = strlen(url);
    char *start = strstr(url, "://"); // find the start of "://<hostname>"
    if (start) {
        start += SKIP_PROTOCOL; // Skip "://"
        char *end = strchr(start, '/'); // Find the char "/"
        if (end) {
            size_t hostnameLen = end - start;
            opts->hostname = (char *) malloc(hostnameLen + END_POSITION);
            if (hostnameLen < maxLen) {
                strncpy(opts->hostname, start, hostnameLen);
                opts->hostname[hostnameLen] = '\0'; // Add the end char to the string
            }
            size_t pathLen = maxLen - (end - url) + END_POSITION;
            opts->path = (char *) malloc(pathLen);
            snprintf(opts->path, pathLen, "%s", end);
        } else {
            // URL does not have path
            size_t urlLen = maxLen - (start - url) + END_POSITION;
            opts->hostname = (char *) malloc(urlLen);
            snprintf(opts->hostname, urlLen, "%s", start);
            opts->path = (char *) malloc(DEFAULT_PATH);
            opts->path[0] = '/';
            opts->path[1] = '\0';
        }
    } else {
        // URL contain INVALID protocol
        errexit("INVALID Protocol", NULL);
    }
}

/* free the allocated space in structure Opts */
void cleanupStruct(struct Opts *opts) {
    if (opts->hostname != NULL) {
        free(opts->hostname);
        opts->hostname = NULL;
    }
    if (opts->path != NULL) {
        free(opts->path);
        opts->path = NULL;
    }
    if (opts->filename != NULL) {
        free(opts->filename);
        opts->filename = NULL;
    }
}

/* check if the protocol is http */
void check_protocol(char *URL) {
    int VALID_Protocol = TRUE;
    if (strlen(URL) >= MIN_URL_LEN) {
        if (URL[0] != 'H' && URL[0] != 'h') {
            VALID_Protocol = FALSE;
        }
        if (URL[1] != 'T' && URL[1] != 't') {
            VALID_Protocol = FALSE;
        }
        if (URL[2] != 'T' && URL[2] != 't') {
            VALID_Protocol = FALSE;
        }
        if (URL[3] != 'P' && URL[3] != 'p') {
            VALID_Protocol = FALSE;
        }
        if (URL[4] != ':') {
            VALID_Protocol = FALSE;
        }
    } else {
        VALID_Protocol = FALSE;
    }
    if (!VALID_Protocol) {
        errexit("INVALID Protocol", NULL);
    }
}

/* extract the opts into a structure */
void parseargs(struct Opts *opts, int argc, char *argv[]) {
    int opt;
    int index = INITIAL_ARGV;
    char *URL, *file;
    opts->u_flag = FALSE;
    opts->d_flag = FALSE;
    opts->q_flag = FALSE;
    opts->r_flag = FALSE;
    opts->f_flag = FALSE;
    opts->o_flag = FALSE;
    opts->C_flag = FALSE;
    if (argc <= MIN_ARGC) {
        fprintf(stderr, "no enough arguments");
        usage(argv[PROJECT_POSITION]);
    } else {
        while (index < argc) {
            if (strlen(argv[index]) == 2) {
                if (argv[index][0] == '-') {
                    if (argv[index][1] == 'o' || argv[index][1] == 'u') {
                        index++;
                    }
                } else {
                    fprintf(stderr, "invalid parameter %s\n", argv[index]);
                    ALL_valid = FALSE;
                }
            } else {
                fprintf(stderr, "invalid parameter %s\n", argv[index]);
                ALL_valid = FALSE;
            }
            index++;
        }
    }
    while ((opt = getopt(argc, argv, "Cfdqru:o:")) != OPTION_END) {
        switch (opt) {
            case 'u':
                opts->u_flag = TRUE;
                URL = optarg;
                break;
            case 'd':
                opts->d_flag = TRUE;
                break;
            case 'q':
                opts->q_flag = TRUE;
                break;
            case 'r':
                opts->r_flag = TRUE;
                break;
            case 'f':
                opts->f_flag = TRUE;
                break;
            case 'o':
                opts->o_flag = TRUE;
                file = optarg;
                break;
            case 'C':
                opts->C_flag = TRUE;
                break;
            case '?':
                ALL_valid = FALSE;
                if (optopt == 'o' || optopt == 'u') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else {
                    fprintf(stderr, "Unknown option -%c\n", optopt);
                }
                break;
            default:
                usage(argv[PROJECT_POSITION]);
        }
    }
    if (!ALL_valid) {
        usage(argv[PROJECT_POSITION]);
    } else {
        if (opts->u_flag)
            extract_hostname_path(URL, opts);
        if (opts->o_flag)
            opts->filename = strdup(file);
    }
}

/* function of debug mode, print out the DBG information if -d option is used */
void debug_mode(struct Opts *opts) {
    if (opts->d_flag) {
        fprintf(stdout, "DBG: host: %s\n", opts->hostname);
        fprintf(stdout, "DBG: web_file: %s\n", opts->path);
        fprintf(stdout, "DBG: output_file: %s\n", opts->filename);
    }
}

/* function of q mode, it will return the request information and print them out if -q option exists */
char *request_mode(struct Opts *opts) {
    size_t max_request_length = strlen(opts->hostname) + strlen(opts->path) + HTTP_REQUEST_LEN;
    // build up the request information
    char request[max_request_length];
    if (opts->C_flag) {
        snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\n"
                                           "Host: %s\r\n"
                                           "User-Agent: CWRU CSDS 325 SimpleClient 1.0\r\n"
                                           "\r\n", opts->path, opts->hostname);
        if (opts->q_flag) {
            fprintf(stdout, "OUT: GET %s HTTP/1.1\n", opts->path);
            fprintf(stdout, "OUT: Host: %s\n", opts->hostname);
            fprintf(stdout, "OUT: User-Agent: CWRU CSDS 325 SimpleClient 1.0\n");
        }
    } else {
        snprintf(request, sizeof(request), "GET %s HTTP/1.0\r\n"
                                           "Host: %s\r\n"
                                           "User-Agent: CWRU CSDS 325 SimpleClient 1.0\r\n"
                                           "\r\n", opts->path, opts->hostname);
        if (opts->q_flag) {
            fprintf(stdout, "OUT: GET %s HTTP/1.0\n", opts->path);
            fprintf(stdout, "OUT: Host: %s\n", opts->hostname);
            fprintf(stdout, "OUT: User-Agent: CWRU CSDS 325 SimpleClient 1.0\n");
        }
    }
    //copy the content to httpRequest
    char *httpRequest = strdup(request);
    return httpRequest;
}

/* read all the information from socket, extend the buffer length if necessary. Process the content in data then */
char *socket_decode(int socket) {
    ssize_t ret;
    size_t buffer_size = BUFLEN;
    bytes_read = INITIAL_BYTE;
    // Dynamically allocate the memory of Buffer, the initial memory size is 1024
    char *Buffer = (char *) malloc(BUFLEN);
    // Initialize the allocated memory
    memset(Buffer, 0x0, BUFLEN);
    while (TRUE) {
        ret = recv(socket, Buffer + bytes_read, buffer_size - bytes_read - 1, 0);
        Buffer[bytes_read + ret] = '\0';
        //printf("read totally %zd byte----------------------------\n", ret);
        if (ret == ERROR_READ) {
            free(Buffer);
            fprintf(stderr, "reading error\n");
            exit(ERROR);
        } else if (ret == COMPLETE_READ) {
            // Complete reading
            break;
        } else {
            bytes_read += ret;
            // Check whether the Buffer needs to be extended
            if (bytes_read == buffer_size - END_POSITION) {
                buffer_size += BUF_EXTEND;
                char *new_buffer = (char *) realloc(Buffer, buffer_size);
                if (new_buffer == NULL) {
                    free(Buffer);
                    fprintf(stderr, "Memory reallocation failed\n");
                    exit(ERROR);
                }
                Buffer = new_buffer;
                // Initialize the reallocated memory
                memset(Buffer + bytes_read, 0x0, buffer_size - bytes_read);
            }
        }
    }
    return Buffer;
}

/* decode the chunked encoding response */
char *decode_chunk(char *response) {
    if (strstr(response, "chunked") != NULL) {
        char *chunk = strstr(response, "\r\n\r\n") + HEADER_END;
        size_t LENGTH = chunk - response;
        char *decoded_data = NULL;
        int decoded_data_len = INITIAL_BYTE;
        int chunk_size;
        size_t new_bytes_size = chunk - response;
        while (TRUE) {
            char *newline_pos = strstr(chunk, "\r\n");
            if (newline_pos == NULL) {
                errexit("can not find the chunk end", NULL);
            }
            char chunk_size_hex[9];
            size_t chunk_header_len = newline_pos - chunk;
            strncpy(chunk_size_hex, chunk, chunk_header_len);
            chunk_size_hex[chunk_header_len] = '\0';
            chunk_size = hex_to_decimal(chunk_size_hex);
            new_bytes_size += (size_t) chunk_size;
            chunk = newline_pos + CHUNK_END;
            if (chunk_size == COMPLETE_READ) {
                break;
            }
            char *new_decoded_data = realloc(decoded_data, decoded_data_len + chunk_size + END_POSITION);
            if (new_decoded_data == NULL) {
                free(decoded_data);
                fprintf(stderr, "Memory reallocation failed\n");
                exit(ERROR);
            }
            decoded_data = new_decoded_data;
            strncpy(decoded_data + decoded_data_len, chunk, chunk_size);
            decoded_data_len += chunk_size;
            decoded_data[decoded_data_len] = '\0';
            chunk += chunk_size + CHUNK_END;
        }
        strncpy(response + LENGTH, decoded_data, strlen(decoded_data));
        response[LENGTH + strlen(decoded_data)] = '\0';
        free(decoded_data);
        bytes_read = new_bytes_size;
    }
    return response;
}

/* function of read mode, read the header line by line if -r option is used */
void response_mode(struct Opts *opts, char *Buffer) {
    // find the end of the header
    char *header_end = strstr(Buffer, "\r\n\r\n");
    if (header_end != NULL) {
        // calculate the length of the header
        size_t header_length = header_end - Buffer + HEADER_END;
        // extract the header
        char header[header_length + END_POSITION];
        strncpy(header, Buffer, header_length);
        header[header_length] = '\0';
        // output each line of the header
        char *line = strtok(header, "\r\n");
        if (strstr(line, "200 OK") != NULL) {
            // output can be written into the output file
            IF_write = TRUE;
            opts->f_flag = FALSE;
        } else {
            if (strstr(line, "301") == NULL) {
                opts->f_flag = FALSE;
            }
        }
        while (line != NULL) {
            if (opts->r_flag)
                fprintf(stdout, "INC: %s\n", line);
            if (opts->f_flag) {
                char *start = strstr(line, "Location:");
                if (start != NULL) {
                    char *new_url = start + LOCATION_LEN;
                    free(opts->path);
                    free(opts->hostname);
                    extract_hostname_path(new_url, opts);
                }
            }
            line = strtok(NULL, "\r\n");
        }
    } else {
        errexit("HTTP response header not found", NULL);
    }
}

/* write the output to the output file */
void write_file(struct Opts *opts, const char *Buffer) {
    if (!opts->f_flag) {
        if (!IF_write)
            errexit("ERROR: non-200 response code", NULL);
        FILE *file = fopen(opts->filename, "wb");
        if (file == NULL) {
            errexit("error opening file", NULL);
        }
        char *header_end = strstr(Buffer, "\r\n\r\n");
        size_t dataLength = bytes_read - (header_end - Buffer) - HEADER_END;
        size_t elementsWritten = fwrite(header_end + HEADER_END, BYTE_LEN, dataLength, file);
        if (elementsWritten != dataLength) {
            fclose(file);
            errexit("error writing to file", NULL);
        }
        fclose(file);
    }
}