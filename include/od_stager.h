#ifndef OD_STAGER_H
#define OD_STAGER_H

#include <stdbool.h>
#include <stdint.h>
#include "od_types.h"

#define OD_STAGER_MAGIC       0x4F445353u
#define OD_STAGER_MAX_TOKEN   256
#define OD_STAGER_MAX_BINARY  (50u * 1024u * 1024u)
#define OD_STAGER_MAX_ARGS    4096
#define OD_STAGER_AUTH_OK     0x01
#define OD_STAGER_AUTH_FAIL   0x00

int od_run_stager_server(const endpoint_t *listen_ep,
                         const char *binary_path,
                         const char *token,
                         const char *args_str,
                         bool single_use, bool verbose);

int od_run_stager_generate(const char *connect_host, uint16_t connect_port,
                           const char *token,
                           const char *os_name,
                           const char *format,
                           const char *run_args);

#endif
