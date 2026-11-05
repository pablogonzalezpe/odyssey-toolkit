#ifndef OD_WS_H
#define OD_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "od_io.h"

#define OD_WS_READ_BUF_SIZE 65536

typedef struct {
    od_io_t underlying;
    bool is_server;
    uint8_t read_buf[OD_WS_READ_BUF_SIZE];
    size_t read_buf_len;
    size_t read_buf_off;
} od_ws_ctx_t;

int od_ws_handshake_server(const od_io_t *underlying, const char *ws_path,
                           char *err_buf, size_t err_buf_sz);
int od_ws_handshake_client(const od_io_t *underlying, const char *host, uint16_t port,
                           const char *ws_path, char *err_buf, size_t err_buf_sz);

void od_ws_init_io(od_io_t *out_io, od_ws_ctx_t *ctx, const od_io_t *underlying, bool is_server);

#endif
