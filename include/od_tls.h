#ifndef OD_TLS_H
#define OD_TLS_H

#include <stdbool.h>
#include <stddef.h>

#include "od_io.h"

typedef enum {
    OD_TLS_MODE_DISABLED = 0,
    OD_TLS_MODE_REQUIRED = 1
} od_tls_mode_t;

typedef struct {
    od_tls_mode_t mode;
    const char *ca_file;
    const char *cert_file;
    const char *key_file;
    const char *server_name;
    bool require_mtls;
} od_tls_options_t;

typedef struct od_tls_state od_tls_state_t;

int od_tls_global_init(void);
void od_tls_global_cleanup(void);
bool od_tls_is_available(void);
const char *od_tls_backend_name(void);
const char *od_tls_mode_name(od_tls_mode_t mode);
int od_tls_parse_mode(const char *raw, od_tls_mode_t *out_mode);

int od_tls_wrap_server_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz);
int od_tls_wrap_client_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz);

void od_tls_state_free(od_tls_state_t *state);

#endif
