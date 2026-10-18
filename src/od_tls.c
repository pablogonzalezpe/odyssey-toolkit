#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od_tls.h"

#ifdef OD_ENABLE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

struct od_tls_state {
    socket_t fd;
#ifdef OD_ENABLE_OPENSSL
    SSL_CTX *ctx;
    SSL *ssl;
#endif
};

static void set_err(char *err_buf, size_t err_buf_sz, const char *msg) {
    if (err_buf == NULL || err_buf_sz == 0) {
        return;
    }
    snprintf(err_buf, err_buf_sz, "%s", msg == NULL ? "unknown error" : msg);
}

const char *od_tls_mode_name(od_tls_mode_t mode) {
    return (mode == OD_TLS_MODE_REQUIRED) ? "required" : "disabled";
}

int od_tls_parse_mode(const char *raw, od_tls_mode_t *out_mode) {
    if (raw == NULL || out_mode == NULL) {
        return -1;
    }
    if (strcmp(raw, "required") == 0) {
        *out_mode = OD_TLS_MODE_REQUIRED;
        return 0;
    }
    if (strcmp(raw, "disabled") == 0) {
        *out_mode = OD_TLS_MODE_DISABLED;
        return 0;
    }
    return -1;
}

int od_tls_global_init(void) {
#ifdef OD_ENABLE_OPENSSL
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return -1;
    }
#endif
    return 0;
}

void od_tls_global_cleanup(void) {
    return;
}

bool od_tls_is_available(void) {
#ifdef OD_ENABLE_OPENSSL
    return true;
#else
    return false;
#endif
}

const char *od_tls_backend_name(void) {
#ifdef OD_ENABLE_OPENSSL
    return "openssl";
#else
    return "none";
#endif
}

#ifndef OD_ENABLE_OPENSSL
int od_tls_wrap_server_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz) {
    (void)fd;
    (void)opts;
    (void)out_io;
    (void)out_state;
    set_err(err_buf, err_buf_sz, "TLS support not compiled in");
    return -1;
}

int od_tls_wrap_client_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz) {
    (void)fd;
    (void)opts;
    (void)out_io;
    (void)out_state;
    set_err(err_buf, err_buf_sz, "TLS support not compiled in");
    return -1;
}

void od_tls_state_free(od_tls_state_t *state) {
    (void)state;
}

#else
static void set_err_ssl(char *err_buf, size_t err_buf_sz, const char *fallback_msg) {
    unsigned long e = ERR_get_error();
    if (e == 0) {
        set_err(err_buf, err_buf_sz, fallback_msg);
        return;
    }
    if (err_buf != NULL && err_buf_sz > 0) {
        ERR_error_string_n(e, err_buf, err_buf_sz);
    }
}

static int wait_for_io(socket_t fd, int want_read) {
    pollfd_t pfd;
    int rc = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = want_read ? OD_SOCK_POLLIN : OD_SOCK_POLLOUT;

    rc = od_socket_poll(&pfd, 1UL, 5000);
    if (rc <= 0) {
        return -1;
    }
    return 0;
}

static int tls_write_all(void *ctx, const uint8_t *buf, size_t len) {
    od_tls_state_t *state = (od_tls_state_t *)ctx;
    size_t off = 0;

    while (off < len) {
        int n = SSL_write(state->ssl, buf + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            continue;
        }

        switch (SSL_get_error(state->ssl, n)) {
            case SSL_ERROR_WANT_READ:
                if (wait_for_io(state->fd, 1) != 0) {
                    return -1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (wait_for_io(state->fd, 0) != 0) {
                    return -1;
                }
                break;
            default:
                return -1;
        }
    }

    return 0;
}

static int tls_read_all(void *ctx, uint8_t *buf, size_t len, bool *out_closed) {
    od_tls_state_t *state = (od_tls_state_t *)ctx;
    size_t off = 0;

    *out_closed = false;
    while (off < len) {
        int n = SSL_read(state->ssl, buf + off, (int)(len - off));
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n == 0) {
            *out_closed = true;
            return 0;
        }

        switch (SSL_get_error(state->ssl, n)) {
            case SSL_ERROR_WANT_READ:
                if (wait_for_io(state->fd, 1) != 0) {
                    return -1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (wait_for_io(state->fd, 0) != 0) {
                    return -1;
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
                *out_closed = true;
                return 0;
            default:
                return -1;
        }
    }

    return 0;
}

static int tls_handshake(od_tls_state_t *state, int is_server, char *err_buf, size_t err_buf_sz) {
    for (;;) {
        int rc = is_server ? SSL_accept(state->ssl) : SSL_connect(state->ssl);
        if (rc == 1) {
            return 0;
        }

        switch (SSL_get_error(state->ssl, rc)) {
            case SSL_ERROR_WANT_READ:
                if (wait_for_io(state->fd, 1) != 0) {
                    set_err(err_buf, err_buf_sz, "TLS handshake timeout/read wait failed");
                    return -1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if (wait_for_io(state->fd, 0) != 0) {
                    set_err(err_buf, err_buf_sz, "TLS handshake timeout/write wait failed");
                    return -1;
                }
                break;
            default:
                set_err_ssl(err_buf, err_buf_sz, "TLS handshake failed");
                return -1;
        }
    }
}

static int tls_load_cert_key(SSL_CTX *ctx, const char *cert_file, const char *key_file,
                             char *err_buf, size_t err_buf_sz) {
    if (cert_file == NULL || key_file == NULL) {
        set_err(err_buf, err_buf_sz, "TLS cert/key required");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        set_err_ssl(err_buf, err_buf_sz, "failed loading TLS cert");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        set_err_ssl(err_buf, err_buf_sz, "failed loading TLS key");
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        set_err(err_buf, err_buf_sz, "TLS cert/key mismatch");
        return -1;
    }

    return 0;
}

static int tls_init_state(socket_t fd, int is_server, const od_tls_options_t *opts, od_io_t *out_io,
                          od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz) {
    od_tls_state_t *state = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int verify_mode = SSL_VERIFY_PEER;

    state = (od_tls_state_t *)calloc(1, sizeof(*state));
    if (state == NULL) {
        set_err(err_buf, err_buf_sz, "out of memory");
        return -1;
    }
    state->fd = fd;

    ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    if (ctx == NULL) {
        set_err_ssl(err_buf, err_buf_sz, "failed creating TLS context");
        goto fail;
    }
    state->ctx = ctx;

    if (opts->ca_file != NULL) {
        if (SSL_CTX_load_verify_locations(ctx, opts->ca_file, NULL) != 1) {
            set_err_ssl(err_buf, err_buf_sz, "failed loading TLS CA");
            goto fail;
        }
    } else if (!is_server) {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            set_err_ssl(err_buf, err_buf_sz, "failed loading default CA paths");
            goto fail;
        }
    }

    if (is_server) {
        if (tls_load_cert_key(ctx, opts->cert_file, opts->key_file, err_buf, err_buf_sz) != 0) {
            goto fail;
        }
        if (opts->require_mtls) {
            if (opts->ca_file == NULL) {
                set_err(err_buf, err_buf_sz, "mTLS requires --tls-ca");
                goto fail;
            }
            verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        } else {
            verify_mode = SSL_VERIFY_NONE;
        }
        SSL_CTX_set_verify(ctx, verify_mode, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if ((opts->cert_file != NULL) ^ (opts->key_file != NULL)) {
            set_err(err_buf, err_buf_sz, "client mTLS needs both --tls-cert and --tls-key");
            goto fail;
        }
        if (opts->cert_file != NULL &&
            tls_load_cert_key(ctx, opts->cert_file, opts->key_file, err_buf, err_buf_sz) != 0) {
            goto fail;
        }
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        set_err_ssl(err_buf, err_buf_sz, "failed creating TLS session");
        goto fail;
    }
    state->ssl = ssl;

    if (SSL_set_fd(ssl, (int)fd) != 1) {
        set_err_ssl(err_buf, err_buf_sz, "failed binding TLS socket");
        goto fail;
    }

    if (!is_server) {
        if (opts->server_name != NULL && opts->server_name[0] != '\0') {
            if (SSL_set_tlsext_host_name(ssl, opts->server_name) != 1) {
                set_err_ssl(err_buf, err_buf_sz, "failed setting TLS server-name");
                goto fail;
            }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            if (SSL_set1_host(ssl, opts->server_name) != 1) {
                set_err_ssl(err_buf, err_buf_sz, "failed setting TLS hostname verification");
                goto fail;
            }
#endif
        }
    }

    if (tls_handshake(state, is_server, err_buf, err_buf_sz) != 0) {
        goto fail;
    }

    out_io->ctx = state;
    out_io->write_all = tls_write_all;
    out_io->read_all = tls_read_all;
    *out_state = state;
    return 0;

fail:
    od_tls_state_free(state);
    return -1;
}

int od_tls_wrap_server_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz) {
    if (opts == NULL || opts->mode != OD_TLS_MODE_REQUIRED) {
        set_err(err_buf, err_buf_sz, "invalid TLS server mode");
        return -1;
    }
    return tls_init_state(fd, 1, opts, out_io, out_state, err_buf, err_buf_sz);
}

int od_tls_wrap_client_socket(socket_t fd, const od_tls_options_t *opts, od_io_t *out_io,
                              od_tls_state_t **out_state, char *err_buf, size_t err_buf_sz) {
    if (opts == NULL || opts->mode != OD_TLS_MODE_REQUIRED) {
        set_err(err_buf, err_buf_sz, "invalid TLS client mode");
        return -1;
    }
    return tls_init_state(fd, 0, opts, out_io, out_state, err_buf, err_buf_sz);
}

void od_tls_state_free(od_tls_state_t *state) {
    if (state == NULL) {
        return;
    }
    if (state->ssl != NULL) {
        SSL_shutdown(state->ssl);
        SSL_free(state->ssl);
        state->ssl = NULL;
    }
    if (state->ctx != NULL) {
        SSL_CTX_free(state->ctx);
        state->ctx = NULL;
    }
    free(state);
}
#endif
