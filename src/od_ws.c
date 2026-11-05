#define _POSIX_C_SOURCE 200809L

#include "od_ws.h"
#include "od_sha1.h"
#include "od_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#else
#include <windows.h>
#include <wincrypt.h>
#endif

#define WS_MAGIC "258EAFA5-E914-47DA-95CA-5AB5E5FE4881"
#define WS_OP_CONTINUATION 0x00
#define WS_OP_TEXT         0x01
#define WS_OP_BINARY       0x02
#define WS_OP_CLOSE        0x08
#define WS_OP_PING         0x09
#define WS_OP_PONG         0x0A
#define WS_FIN_BIT         0x80
#define WS_MASK_BIT        0x80
#define HTTP_BUF_SIZE      4096

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_sz) {
    size_t i, j = 0;
    for (i = 0; i + 2 < in_len && j + 4 < out_sz; i += 3) {
        out[j++] = b64_table[(in[i] >> 2) & 0x3F];
        out[j++] = b64_table[((in[i] & 0x03) << 4) | ((in[i + 1] >> 4) & 0x0F)];
        out[j++] = b64_table[((in[i + 1] & 0x0F) << 2) | ((in[i + 2] >> 6) & 0x03)];
        out[j++] = b64_table[in[i + 2] & 0x3F];
    }
    if (i < in_len && j + 4 < out_sz) {
        out[j++] = b64_table[(in[i] >> 2) & 0x3F];
        if (i + 1 < in_len) {
            out[j++] = b64_table[((in[i] & 0x03) << 4) | ((in[i + 1] >> 4) & 0x0F)];
            out[j++] = b64_table[((in[i + 1] & 0x0F) << 2)];
        } else {
            out[j++] = b64_table[((in[i] & 0x03) << 4)];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    if (j < out_sz) out[j] = '\0';
    return j;
}

static void generate_random_bytes(uint8_t *buf, size_t len) {
#ifndef _WIN32
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t n = read(fd, buf + off, len - off);
            if (n > 0) off += (size_t)n;
            else break;
        }
        close(fd);
        if (off == len) return;
    }
#else
    HCRYPTPROV prov;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(prov, (DWORD)len, buf);
        CryptReleaseContext(prov, 0);
        return;
    }
#endif
    {
        size_t i;
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)((uintptr_t)buf & 0xFFFFFFFF);
        for (i = 0; i < len; i++) {
            seed = seed * 1103515245 + 12345;
            buf[i] = (uint8_t)(seed >> 16);
        }
    }
}

static uint32_t generate_mask_key(void) {
    uint32_t key;
    generate_random_bytes((uint8_t *)&key, sizeof(key));
    return key;
}

static void compute_accept_key(const char *client_key, char *out, size_t out_sz) {
    char concat[256];
    uint8_t hash[20];
    snprintf(concat, sizeof(concat), "%s%s", client_key, WS_MAGIC);
    od_sha1((const uint8_t *)concat, strlen(concat), hash);
    b64_encode(hash, 20, out, out_sz);
}

static int io_read_byte(const od_io_t *io, uint8_t *byte, bool *closed) {
    return io->read_all(io->ctx, byte, 1, closed);
}

static int read_http_line(const od_io_t *io, char *buf, size_t buf_sz, bool *closed) {
    size_t pos = 0;
    while (pos + 1 < buf_sz) {
        uint8_t c;
        if (io_read_byte(io, &c, closed) != 0 || *closed) return -1;
        buf[pos++] = (char)c;
        if (pos >= 2 && buf[pos - 2] == '\r' && buf[pos - 1] == '\n') {
            buf[pos] = '\0';
            return 0;
        }
    }
    return -1;
}

static const char *find_header_value(const char *headers, const char *name) {
    const char *p = headers;
    size_t name_len = strlen(name);
    while (*p) {
        if (strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (*v == ' ' || *v == '\t') v++;
            return v;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return NULL;
}

static int extract_header(const char *headers, const char *name, char *out, size_t out_sz) {
    const char *v = find_header_value(headers, name);
    if (v == NULL) return -1;
    size_t i = 0;
    while (v[i] && v[i] != '\r' && v[i] != '\n' && i + 1 < out_sz) {
        out[i] = v[i];
        i++;
    }
    out[i] = '\0';
    return 0;
}

int od_ws_handshake_client(const od_io_t *underlying, const char *host, uint16_t port,
                           const char *ws_path, char *err_buf, size_t err_buf_sz) {
    uint8_t key_raw[16];
    char key_b64[32];
    char request[HTTP_BUF_SIZE];
    char headers[HTTP_BUF_SIZE];
    char line[1024];
    char expected_accept[64];
    char got_accept[64];
    bool closed = false;
    size_t headers_len = 0;
    int len;

    if (ws_path == NULL || ws_path[0] == '\0') ws_path = "/";

    generate_random_bytes(key_raw, sizeof(key_raw));
    b64_encode(key_raw, sizeof(key_raw), key_b64, sizeof(key_b64));
    compute_accept_key(key_b64, expected_accept, sizeof(expected_accept));

    len = snprintf(request, sizeof(request),
                   "GET %s HTTP/1.1\r\n"
                   "Host: %s:%u\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "\r\n",
                   ws_path, host, (unsigned)port, key_b64);

    if (underlying->write_all(underlying->ctx, (const uint8_t *)request, (size_t)len) != 0) {
        snprintf(err_buf, err_buf_sz, "failed to send WS upgrade request");
        return -1;
    }

    if (read_http_line(underlying, line, sizeof(line), &closed) != 0 || closed) {
        snprintf(err_buf, err_buf_sz, "failed to read HTTP status line");
        return -1;
    }
    if (strstr(line, "101") == NULL) {
        snprintf(err_buf, err_buf_sz, "expected HTTP 101, got: %.80s", line);
        return -1;
    }

    memset(headers, 0, sizeof(headers));
    for (;;) {
        if (read_http_line(underlying, line, sizeof(line), &closed) != 0 || closed) {
            snprintf(err_buf, err_buf_sz, "failed reading response headers");
            return -1;
        }
        if (strcmp(line, "\r\n") == 0) break;
        size_t ll = strlen(line);
        if (headers_len + ll < sizeof(headers)) {
            memcpy(headers + headers_len, line, ll);
            headers_len += ll;
        }
    }

    memset(got_accept, 0, sizeof(got_accept));
    if (extract_header(headers, "Sec-WebSocket-Accept", got_accept, sizeof(got_accept)) != 0) {
        snprintf(err_buf, err_buf_sz, "missing Sec-WebSocket-Accept header");
        return -1;
    }
    if (strcmp(got_accept, expected_accept) != 0) {
        snprintf(err_buf, err_buf_sz, "Sec-WebSocket-Accept mismatch");
        return -1;
    }

    return 0;
}

int od_ws_handshake_server(const od_io_t *underlying, const char *ws_path,
                           char *err_buf, size_t err_buf_sz) {
    char headers[HTTP_BUF_SIZE];
    char line[1024];
    char client_key[64];
    char accept_key[64];
    char response[512];
    bool closed = false;
    size_t headers_len = 0;
    int len;

    if (read_http_line(underlying, line, sizeof(line), &closed) != 0 || closed) {
        snprintf(err_buf, err_buf_sz, "failed to read HTTP request line");
        return -1;
    }

    if (strncmp(line, "GET ", 4) != 0) {
        snprintf(err_buf, err_buf_sz, "expected GET request, got: %.40s", line);
        return -1;
    }

    if (ws_path != NULL && ws_path[0] != '\0') {
        size_t path_len = strlen(ws_path);
        if (strncmp(line + 4, ws_path, path_len) != 0 ||
            (line[4 + path_len] != ' ' && line[4 + path_len] != '?')) {
            snprintf(err_buf, err_buf_sz, "WS path mismatch: expected %s", ws_path);
            return -1;
        }
    }

    memset(headers, 0, sizeof(headers));
    for (;;) {
        if (read_http_line(underlying, line, sizeof(line), &closed) != 0 || closed) {
            snprintf(err_buf, err_buf_sz, "failed reading request headers");
            return -1;
        }
        if (strcmp(line, "\r\n") == 0) break;
        size_t ll = strlen(line);
        if (headers_len + ll < sizeof(headers)) {
            memcpy(headers + headers_len, line, ll);
            headers_len += ll;
        }
    }

    memset(client_key, 0, sizeof(client_key));
    if (extract_header(headers, "Sec-WebSocket-Key", client_key, sizeof(client_key)) != 0) {
        snprintf(err_buf, err_buf_sz, "missing Sec-WebSocket-Key header");
        return -1;
    }

    compute_accept_key(client_key, accept_key, sizeof(accept_key));

    len = snprintf(response, sizeof(response),
                   "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: %s\r\n"
                   "\r\n",
                   accept_key);

    if (underlying->write_all(underlying->ctx, (const uint8_t *)response, (size_t)len) != 0) {
        snprintf(err_buf, err_buf_sz, "failed to send WS upgrade response");
        return -1;
    }

    return 0;
}

static int ws_write_frame(const od_io_t *underlying, bool mask_payload,
                          uint8_t opcode, const uint8_t *payload, size_t payload_len) {
    uint8_t hdr[14];
    size_t hdr_len = 0;

    hdr[0] = WS_FIN_BIT | (opcode & 0x0F);
    hdr_len = 1;

    if (payload_len < 126) {
        hdr[1] = (uint8_t)payload_len;
        if (mask_payload) hdr[1] |= WS_MASK_BIT;
        hdr_len = 2;
    } else if (payload_len <= 0xFFFF) {
        hdr[1] = 126;
        if (mask_payload) hdr[1] |= WS_MASK_BIT;
        hdr[2] = (uint8_t)(payload_len >> 8);
        hdr[3] = (uint8_t)(payload_len);
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        if (mask_payload) hdr[1] |= WS_MASK_BIT;
        hdr[2] = 0; hdr[3] = 0; hdr[4] = 0; hdr[5] = 0;
        hdr[6] = (uint8_t)(payload_len >> 24);
        hdr[7] = (uint8_t)(payload_len >> 16);
        hdr[8] = (uint8_t)(payload_len >> 8);
        hdr[9] = (uint8_t)(payload_len);
        hdr_len = 10;
    }

    if (mask_payload) {
        uint32_t mask = generate_mask_key();
        memcpy(hdr + hdr_len, &mask, 4);
        hdr_len += 4;

        if (underlying->write_all(underlying->ctx, hdr, hdr_len) != 0) return -1;

        if (payload_len > 0) {
            uint8_t *masked = (uint8_t *)malloc(payload_len);
            if (masked == NULL) return -1;
            uint8_t *mk = (uint8_t *)&mask;
            size_t i;
            for (i = 0; i < payload_len; i++) {
                masked[i] = payload[i] ^ mk[i & 3];
            }
            int rc = underlying->write_all(underlying->ctx, masked, payload_len);
            free(masked);
            return rc;
        }
        return 0;
    }

    if (underlying->write_all(underlying->ctx, hdr, hdr_len) != 0) return -1;
    if (payload_len > 0) {
        return underlying->write_all(underlying->ctx, payload, payload_len);
    }
    return 0;
}

static int ws_read_frame(const od_io_t *underlying, uint8_t *opcode_out,
                         uint8_t *payload_buf, size_t payload_buf_sz,
                         size_t *payload_len_out, bool *closed) {
    uint8_t hdr[2];
    uint8_t mask_key[4];
    bool has_mask;
    uint64_t payload_len;

    *closed = false;

    if (underlying->read_all(underlying->ctx, hdr, 2, closed) != 0 || *closed) return -1;

    *opcode_out = hdr[0] & 0x0F;
    has_mask = (hdr[1] & WS_MASK_BIT) != 0;
    payload_len = hdr[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (underlying->read_all(underlying->ctx, ext, 2, closed) != 0 || *closed) return -1;
        payload_len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (underlying->read_all(underlying->ctx, ext, 8, closed) != 0 || *closed) return -1;
        payload_len = 0;
        {
            int i;
            for (i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | ext[i];
            }
        }
    }

    if (has_mask) {
        if (underlying->read_all(underlying->ctx, mask_key, 4, closed) != 0 || *closed) return -1;
    }

    if (payload_len > payload_buf_sz) {
        od_log_error("ws: frame too large: %llu bytes", (unsigned long long)payload_len);
        return -1;
    }

    *payload_len_out = (size_t)payload_len;
    if (payload_len > 0) {
        if (underlying->read_all(underlying->ctx, payload_buf, (size_t)payload_len, closed) != 0 || *closed)
            return -1;
        if (has_mask) {
            size_t i;
            for (i = 0; i < (size_t)payload_len; i++) {
                payload_buf[i] ^= mask_key[i & 3];
            }
        }
    }

    return 0;
}

static int od_ws_write_all(void *ctx, const uint8_t *buf, size_t len) {
    od_ws_ctx_t *ws = (od_ws_ctx_t *)ctx;
    bool mask = !ws->is_server;
    return ws_write_frame(&ws->underlying, mask, WS_OP_BINARY, buf, len);
}

static int od_ws_read_all(void *ctx, uint8_t *buf, size_t len, bool *out_closed) {
    od_ws_ctx_t *ws = (od_ws_ctx_t *)ctx;
    size_t filled = 0;

    *out_closed = false;

    while (filled < len) {
        size_t avail = ws->read_buf_len - ws->read_buf_off;
        if (avail > 0) {
            size_t want = len - filled;
            size_t take = avail < want ? avail : want;
            memcpy(buf + filled, ws->read_buf + ws->read_buf_off, take);
            ws->read_buf_off += take;
            filled += take;
            if (ws->read_buf_off == ws->read_buf_len) {
                ws->read_buf_off = 0;
                ws->read_buf_len = 0;
            }
            continue;
        }

        for (;;) {
            uint8_t opcode;
            size_t frame_len = 0;
            bool closed = false;
            if (ws_read_frame(&ws->underlying, &opcode, ws->read_buf,
                              OD_WS_READ_BUF_SIZE, &frame_len, &closed) != 0 || closed) {
                *out_closed = closed;
                return closed ? 0 : -1;
            }

            if (opcode == WS_OP_PING) {
                bool mask = !ws->is_server;
                if (ws_write_frame(&ws->underlying, mask, WS_OP_PONG,
                                   ws->read_buf, frame_len) != 0) {
                    return -1;
                }
                continue;
            }
            if (opcode == WS_OP_PONG) {
                continue;
            }
            if (opcode == WS_OP_CLOSE) {
                bool mask = !ws->is_server;
                (void)ws_write_frame(&ws->underlying, mask, WS_OP_CLOSE, NULL, 0);
                *out_closed = true;
                return 0;
            }
            if (opcode == WS_OP_BINARY || opcode == WS_OP_TEXT || opcode == WS_OP_CONTINUATION) {
                ws->read_buf_len = frame_len;
                ws->read_buf_off = 0;
                break;
            }

            od_log_warn("ws: ignoring unknown opcode 0x%02x", opcode);
        }
    }

    return 0;
}

void od_ws_init_io(od_io_t *out_io, od_ws_ctx_t *ctx, const od_io_t *underlying, bool is_server) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->underlying = *underlying;
    ctx->is_server = is_server;
    ctx->read_buf_len = 0;
    ctx->read_buf_off = 0;

    out_io->ctx = ctx;
    out_io->write_all = od_ws_write_all;
    out_io->read_all = od_ws_read_all;
}
