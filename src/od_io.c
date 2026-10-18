#define _POSIX_C_SOURCE 200809L

#include "od_io.h"

void od_io_init_socket(od_io_t *io, od_socket_io_ctx_t *ctx, socket_t fd) {
    ctx->fd = fd;
    io->ctx = ctx;
    io->write_all = od_io_socket_write_all;
    io->read_all = od_io_socket_read_all;
}

int od_io_socket_write_all(void *ctx, const uint8_t *buf, size_t len) {
    od_socket_io_ctx_t *sctx = (od_socket_io_ctx_t *)ctx;
    size_t off = 0;

    while (off < len) {
        int n = send(sctx->fd, (const char *)(buf + off), (int)(len - off), 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0) {
            return -1;
        }
        if (od_socket_error_is_retryable(od_socket_last_error())) {
            continue;
        }
        od_socket_log_error("send");
        return -1;
    }

    return 0;
}

int od_io_socket_read_all(void *ctx, uint8_t *buf, size_t len, bool *out_closed) {
    od_socket_io_ctx_t *sctx = (od_socket_io_ctx_t *)ctx;
    size_t off = 0;

    *out_closed = false;
    while (off < len) {
        int n = recv(sctx->fd, (char *)(buf + off), (int)(len - off), 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0) {
            *out_closed = true;
            return 0;
        }
        if (od_socket_error_is_retryable(od_socket_last_error())) {
            continue;
        }
        od_socket_log_error("recv");
        return -1;
    }

    return 0;
}
