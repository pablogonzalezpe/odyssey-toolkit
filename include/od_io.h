#ifndef OD_IO_H
#define OD_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "od_socket.h"

typedef int (*od_io_write_all_fn)(void *ctx, const uint8_t *buf, size_t len);
typedef int (*od_io_read_all_fn)(void *ctx, uint8_t *buf, size_t len, bool *out_closed);

typedef struct {
    void *ctx;
    od_io_write_all_fn write_all;
    od_io_read_all_fn read_all;
} od_io_t;

typedef struct {
    socket_t fd;
} od_socket_io_ctx_t;

void od_io_init_socket(od_io_t *io, od_socket_io_ctx_t *ctx, socket_t fd);
int od_io_socket_write_all(void *ctx, const uint8_t *buf, size_t len);
int od_io_socket_read_all(void *ctx, uint8_t *buf, size_t len, bool *out_closed);

#endif
