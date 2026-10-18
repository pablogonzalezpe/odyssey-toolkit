#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#endif

#include "od_relay.h"
#include "od_reverse.h"
#include "od_knock.h"
#include "od_hardening.h"
#include "od_gateway.h"
#include "od_log.h"
#include "od_socket.h"
#include "od_tls.h"
#include "od_tun.h"
#include "od_tun_dev.h"
#include "od_types.h"

#define ODYSSEY_VERSION "0.1.0"

#define DEFAULT_CONNECT_TIMEOUT_MS 5000
#define DEFAULT_HEARTBEAT_MS 5000
#define DEFAULT_HEARTBEAT_TIMEOUT_MS 15000
#define DEFAULT_MAX_STREAMS 128

static void print_version(void) {
    printf("odyssey %s\n", ODYSSEY_VERSION);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s relay --listen IP:PORT --to IP:PORT [--connect-timeout-ms N]\n"
            "      [--allow-source IP|CIDR]... [--rate-limit-per-min N]\n"
            "      [--knock-seq P1,P2,...] [--knock-timeout-ms N] [--knock-open-ms N]\n"
            "      [--log-format text|json] [--verbose]\n"
            "  %s reverse-server --listen-control IP:PORT --token-file PATH\n"
            "      [--bind LHOST:LPORT:RHOST:RPORT]... [--max-streams N]\n"
            "      [--socks-listen HOST:PORT]\n"
            "      [--socks-user USER --socks-pass-file PATH]\n"
            "      [--admin-listen HOST:PORT --admin-token-file PATH]\n"
            "      [--control-admin enabled|disabled]\n"
            "      [--control-admin-token-file PATH] [--control-admin-max-binds N]\n"
            "      [--control-admin-require-token enabled|disabled]\n"
            "      [--control-admin-rate-limit-per-min N]\n"
            "      [--allow-source IP|CIDR]... [--rate-limit-per-min N]\n"
            "      [--knock-seq P1,P2,...] [--knock-timeout-ms N] [--knock-open-ms N]\n"
            "      [--tls-mode required|disabled] [--tls-cert PATH] [--tls-key PATH]\n"
            "      [--tls-ca PATH] [--require-mtls]\n"
            "      [--heartbeat-ms N] [--heartbeat-timeout-ms N]\n"
            "      [--log-format text|json] [--verbose]\n"
            "  %s gateway --listen-control IP:PORT --token-file PATH\n"
            "      --tun-name NAME --tun-cidr CIDR --route-allow CIDR [--route-allow CIDR]...\n"
            "      [--gateway-mtu N]\n"
            "      [--admin-listen HOST:PORT --admin-token-file PATH]\n"
            "      [--control-admin enabled|disabled]\n"
            "      [--control-admin-token-file PATH] [--control-admin-require-token enabled|disabled]\n"
            "      [--control-admin-rate-limit-per-min N]\n"
            "      [--tls-mode required|disabled] [--tls-cert PATH] [--tls-key PATH] [--tls-ca PATH]\n"
            "      [--heartbeat-ms N] [--heartbeat-timeout-ms N]\n"
            "      [--log-format text|json] [--verbose]\n"
            "  %s reverse-client --connect IP:PORT --token-file PATH\n"
            "      [--mode reverse|tun-agent]\n"
            "      [--allow-cidr CIDR]... [--allow-port tcp:PORT|udp:PORT]... [--agent-name NAME]\n"
            "      [--agent-tun-cidr CIDR]\n"
            "      [--allow-target HOST:PORT]... [--max-streams N]\n"
            "      [--knock-before-connect] [--knock-host HOST] [--knock-seq P1,P2,...]\n"
            "      [--knock-delay-ms N] [--knock-timeout-ms N]\n"
            "      [--ctl-list-bind] [--ctl-add-bind SPEC]... [--ctl-del-bind ID]...\n"
            "      [--ctl-capabilities] [--ctl-status]\n"
            "      [--ctl-list-stream] [--ctl-close-stream ID]...\n"
            "      [--ctl-route-list] [--ctl-route-add CIDR]... [--ctl-route-del CIDR]...\n"
            "      [--ctl-policy-show]\n"
            "      [--ctl-policy-allow-cidr-add CIDR]... [--ctl-policy-allow-cidr-del CIDR]...\n"
            "      [--ctl-policy-allow-port-add tcp:PORT|udp:PORT]... [--ctl-policy-allow-port-del tcp:PORT|udp:PORT]...\n"
            "      [--ctl-killswitch on|off] [--ctl-snapshot]\n"
            "      [--ctl-exit-after-admin]\n"
            "      [--ctl-token-file PATH]\n"
            "      [--tls-mode required|disabled] [--tls-ca PATH]\n"
            "      [--tls-server-name NAME] [--tls-cert PATH] [--tls-key PATH]\n"
            "      [--connect-timeout-ms N] [--heartbeat-timeout-ms N]\n"
            "      [--log-format text|json] [--verbose]\n\n"
            "  %s knock --host HOST --seq P1,P2,...\n"
            "      [--delay-ms N] [--timeout-ms N] [--log-format text|json] [--verbose]\n\n"
            "  %s admin --connect IP:PORT [--token-file PATH] CMD\n"
            "      CMD: list-bind | add-bind LHOST:LPORT:RHOST:RPORT | del-bind BIND_ID |\n"
            "           capabilities | status | list-stream | close-stream STREAM_ID |\n"
            "           route-list | route-add CIDR | route-del CIDR |\n"
            "           policy-show |\n"
            "           policy-allow-cidr-add CIDR | policy-allow-cidr-del CIDR |\n"
            "           policy-allow-port-add tcp:PORT|udp:PORT | policy-allow-port-del tcp:PORT|udp:PORT |\n"
            "           killswitch on|off | snapshot\n\n"
            "  %s --version\n\n"
            "Notes:\n"
            "  - IPv4/hostname only in this MVP endpoint format.\n"
            "  - Default connect timeout: %d ms.\n"
            "  - Default heartbeat: %d ms (timeout %d ms).\n"
            "  - Default max streams: %d.\n"
            "  - Default reverse TLS mode: required.\n\n"
            "Odyssey %s — https://github.com/pablogonzalezpe/odyssey\n",
            prog, prog, prog, prog, prog, prog, prog, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_HEARTBEAT_MS,
            DEFAULT_HEARTBEAT_TIMEOUT_MS, DEFAULT_MAX_STREAMS, ODYSSEY_VERSION);
}

static int parse_endpoint(const char *raw, endpoint_t *out) {
    const char *sep = strrchr(raw, ':');
    char port_buf[16];
    char *endptr = NULL;
    unsigned long p = 0;
    size_t host_len = 0;

    if (sep == NULL || sep == raw || *(sep + 1) == '\0') {
        return -1;
    }

    host_len = (size_t)(sep - raw);
    if (host_len >= sizeof(out->host)) {
        return -1;
    }

    memcpy(out->host, raw, host_len);
    out->host[host_len] = '\0';

    snprintf(port_buf, sizeof(port_buf), "%s", sep + 1);
    errno = 0;
    p = strtoul(port_buf, &endptr, 10);
    if (errno != 0 || endptr == port_buf || *endptr != '\0' || p > 65535UL || p == 0UL) {
        return -1;
    }

    out->port = (uint16_t)p;
    return 0;
}

static int parse_u32_arg(const char *raw, unsigned long min, unsigned long max, int *out) {
    char *endptr = NULL;
    unsigned long v = 0;

    errno = 0;
    v = strtoul(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || *endptr != '\0' || v < min || v > max) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

typedef struct {
    char **allow_sources;
    size_t allow_source_count;
    size_t allow_source_cap;
    uint16_t *knock_ports;
    size_t knock_count;
    int rate_limit_per_min;
    int knock_timeout_ms;
    int knock_open_ms;
} cli_hardening_opts_t;

static void cli_hardening_init(cli_hardening_opts_t *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->rate_limit_per_min = 0;
    opts->knock_timeout_ms = 5000;
    opts->knock_open_ms = 30000;
}

static void cli_hardening_free(cli_hardening_opts_t *opts) {
    size_t i = 0;
    if (opts == NULL) {
        return;
    }
    for (i = 0; i < opts->allow_source_count; i++) {
        free(opts->allow_sources[i]);
    }
    free(opts->allow_sources);
    free(opts->knock_ports);
    memset(opts, 0, sizeof(*opts));
}

static int parse_log_format_arg(const char *raw, od_log_format_t *out) {
    if (strcmp(raw, "text") == 0) {
        *out = OD_LOG_FORMAT_TEXT;
        return 0;
    }
    if (strcmp(raw, "json") == 0) {
        *out = OD_LOG_FORMAT_JSON;
        return 0;
    }
    return -1;
}

static char *dup_string_local(const char *src) {
    size_t len = 0;
    char *dst = NULL;
    if (src == NULL) {
        return NULL;
    }
    len = strlen(src);
    dst = (char *)calloc(len + 1, 1);
    if (dst == NULL) {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

static int cli_hardening_add_allow_source(cli_hardening_opts_t *opts, const char *raw) {
    char **new_arr = NULL;
    char *dup = NULL;
    if (od_hardening_validate_source_spec(raw) != 0) {
        return -1;
    }
    if (opts->allow_source_count == opts->allow_source_cap) {
        size_t new_cap = (opts->allow_source_cap == 0) ? 8 : (opts->allow_source_cap * 2);
        new_arr = (char **)realloc(opts->allow_sources, new_cap * sizeof(*new_arr));
        if (new_arr == NULL) {
            return -1;
        }
        opts->allow_sources = new_arr;
        opts->allow_source_cap = new_cap;
    }
    dup = dup_string_local(raw);
    if (dup == NULL) {
        return -1;
    }
    opts->allow_sources[opts->allow_source_count++] = dup;
    return 0;
}

static int parse_knock_seq_arg(const char *raw, cli_hardening_opts_t *opts) {
    char copy[512];
    char *token = NULL;
    char *next = NULL;
    size_t count = 0;
    uint16_t parsed[32];

    memset(copy, 0, sizeof(copy));
    memset(parsed, 0, sizeof(parsed));
    if (strlen(raw) >= sizeof(copy)) {
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", raw);

    token = copy;
    while (token != NULL) {
        char *endptr = NULL;
        unsigned long p = 0;
        next = strchr(token, ',');
        if (next != NULL) {
            *next = '\0';
            next++;
        }
        if (*token == '\0' || count >= (sizeof(parsed) / sizeof(parsed[0]))) {
            return -1;
        }
        p = strtoul(token, &endptr, 10);
        if (endptr == token || *endptr != '\0' || p == 0UL || p > 65535UL) {
            return -1;
        }
        parsed[count++] = (uint16_t)p;
        token = next;
    }

    if (count < 2) {
        return -1;
    }

    free(opts->knock_ports);
    opts->knock_ports = (uint16_t *)calloc(count, sizeof(*opts->knock_ports));
    if (opts->knock_ports == NULL) {
        opts->knock_count = 0;
        return -1;
    }
    memcpy(opts->knock_ports, parsed, count * sizeof(parsed[0]));
    opts->knock_count = count;
    return 0;
}

static void fill_hardening_options(const cli_hardening_opts_t *cli, bool verbose,
                                   od_hardening_options_t *out) {
    memset(out, 0, sizeof(*out));
    out->allow_sources = (const char *const *)cli->allow_sources;
    out->allow_source_count = cli->allow_source_count;
    out->rate_limit_per_min = cli->rate_limit_per_min;
    out->knock_ports = cli->knock_ports;
    out->knock_count = cli->knock_count;
    out->knock_timeout_ms = cli->knock_timeout_ms;
    out->knock_open_ms = cli->knock_open_ms;
    out->verbose = verbose;
}

typedef struct {
    bool enabled;
    bool have_host;
    char host[256];
    uint16_t *ports;
    size_t port_count;
    int delay_ms;
    int timeout_ms;
} cli_knock_opts_t;

static void cli_knock_init(cli_knock_opts_t *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->delay_ms = 120;
    opts->timeout_ms = 1000;
}

static void cli_knock_free(cli_knock_opts_t *opts) {
    if (opts == NULL) {
        return;
    }
    free(opts->ports);
    memset(opts, 0, sizeof(*opts));
}

static int parse_port_seq_arg(const char *raw, size_t min_ports, uint16_t **out_ports,
                              size_t *out_count) {
    char copy[512];
    char *token = NULL;
    char *next = NULL;
    size_t count = 0;
    uint16_t parsed[64];
    uint16_t *ports = NULL;

    if (raw == NULL || out_ports == NULL || out_count == NULL) {
        return -1;
    }
    *out_ports = NULL;
    *out_count = 0;
    memset(copy, 0, sizeof(copy));
    memset(parsed, 0, sizeof(parsed));

    if (strlen(raw) >= sizeof(copy)) {
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", raw);

    token = copy;
    while (token != NULL) {
        char *endptr = NULL;
        unsigned long p = 0;
        next = strchr(token, ',');
        if (next != NULL) {
            *next = '\0';
            next++;
        }
        if (*token == '\0' || count >= (sizeof(parsed) / sizeof(parsed[0]))) {
            return -1;
        }
        p = strtoul(token, &endptr, 10);
        if (endptr == token || *endptr != '\0' || p == 0UL || p > 65535UL) {
            return -1;
        }
        parsed[count++] = (uint16_t)p;
        token = next;
    }

    if (count < min_ports) {
        return -1;
    }

    ports = (uint16_t *)calloc(count, sizeof(*ports));
    if (ports == NULL) {
        return -1;
    }
    memcpy(ports, parsed, count * sizeof(parsed[0]));
    *out_ports = ports;
    *out_count = count;
    return 0;
}

static int ctrl_action_add(od_ctrl_action_t **actions, size_t *count, size_t *cap,
                           od_ctrl_action_type_t type, const char *value) {
    od_ctrl_action_t *new_arr = NULL;
    od_ctrl_action_t *a = NULL;
    if (*count == *cap) {
        size_t new_cap = (*cap == 0) ? 4 : (*cap * 2);
        new_arr = (od_ctrl_action_t *)realloc(*actions, new_cap * sizeof(*new_arr));
        if (new_arr == NULL) {
            return -1;
        }
        *actions = new_arr;
        *cap = new_cap;
    }
    a = &(*actions)[*count];
    memset(a, 0, sizeof(*a));
    a->type = type;
    if (value != NULL) {
        if (strlen(value) >= sizeof(a->value)) {
            return -1;
        }
        snprintf(a->value, sizeof(a->value), "%s", value);
    }
    (*count)++;
    return 0;
}

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} cli_string_list_t;

static void cli_string_list_free(cli_string_list_t *list) {
    size_t i = 0;
    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static int cli_string_list_add(cli_string_list_t *list, const char *value) {
    char **new_items = NULL;
    char *dup = NULL;
    if (list == NULL || value == NULL || value[0] == '\0') {
        return -1;
    }
    if (list->count == list->cap) {
        size_t new_cap = (list->cap == 0) ? 8 : (list->cap * 2);
        new_items = (char **)realloc(list->items, new_cap * sizeof(*new_items));
        if (new_items == NULL) {
            return -1;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    dup = dup_string_local(value);
    if (dup == NULL) {
        return -1;
    }
    list->items[list->count++] = dup;
    return 0;
}

static int parse_bind_rule(const char *raw, od_bind_rule_t *out) {
    char copy[1024];
    char *parts[4];
    int idx = 0;
    char *p = NULL;
    char *endptr = NULL;
    unsigned long lp = 0;
    unsigned long rp = 0;

    memset(copy, 0, sizeof(copy));
    memset(out, 0, sizeof(*out));
    snprintf(copy, sizeof(copy), "%s", raw);

    parts[idx++] = copy;
    p = copy;
    while (*p != '\0' && idx < 4) {
        if (*p == ':') {
            *p = '\0';
            parts[idx++] = p + 1;
        }
        p++;
    }
    if (idx != 4) {
        return -1;
    }

    if (strlen(parts[0]) == 0 || strlen(parts[0]) >= sizeof(out->listen_ep.host) ||
        strlen(parts[2]) == 0 || strlen(parts[2]) >= sizeof(out->target_ep.host)) {
        return -1;
    }

    errno = 0;
    lp = strtoul(parts[1], &endptr, 10);
    if (errno != 0 || endptr == parts[1] || *endptr != '\0' || lp == 0UL || lp > 65535UL) {
        return -1;
    }

    errno = 0;
    rp = strtoul(parts[3], &endptr, 10);
    if (errno != 0 || endptr == parts[3] || *endptr != '\0' || rp == 0UL || rp > 65535UL) {
        return -1;
    }

    memcpy(out->listen_ep.host, parts[0], strlen(parts[0]));
    out->listen_ep.host[strlen(parts[0])] = '\0';
    out->listen_ep.port = (uint16_t)lp;
    memcpy(out->target_ep.host, parts[2], strlen(parts[2]));
    out->target_ep.host[strlen(parts[2])] = '\0';
    out->target_ep.port = (uint16_t)rp;
    return 0;
}

static char *read_token_file(const char *path) {
    FILE *f = NULL;
    long sz = 0;
    size_t nread = 0;
    char *buf = NULL;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "Could not open token file: %s\n", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    buf = (char *)calloc((size_t)sz + 1, 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[nread] = '\0';

    while (nread > 0 &&
           (buf[nread - 1] == '\n' || buf[nread - 1] == '\r' || buf[nread - 1] == ' ' ||
            buf[nread - 1] == '\t')) {
        buf[nread - 1] = '\0';
        nread--;
    }

    if (nread == 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

static int ascii_strcasecmp_local(const char *a, const char *b) {
    unsigned char ca = 0;
    unsigned char cb = 0;
    while (*a != '\0' && *b != '\0') {
        ca = (unsigned char)tolower((unsigned char)*a);
        cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb) {
            return (int)ca - (int)cb;
        }
        a++;
        b++;
    }
    ca = (unsigned char)tolower((unsigned char)*a);
    cb = (unsigned char)tolower((unsigned char)*b);
    return (int)ca - (int)cb;
}

static int validate_token_policy(const char *token, char *reason_buf, size_t reason_buf_sz) {
    static const char *weak_tokens[] = {
        "demo",
        "demotoken",
        "odyssey-demo-token",
        "changeme",
        "password",
        "secret",
        "token",
        "1234567890123456",
        "abcdefghijklmnop"
    };
    size_t i = 0;
    size_t len = 0;
    char lower[256];

    if (token == NULL) {
        snprintf(reason_buf, reason_buf_sz, "token is null");
        return -1;
    }

    len = strlen(token);
    if (len < 16) {
        snprintf(reason_buf, reason_buf_sz, "token too short (min 16 chars)");
        return -1;
    }

    for (i = 0; i < sizeof(weak_tokens) / sizeof(weak_tokens[0]); i++) {
        if (ascii_strcasecmp_local(token, weak_tokens[i]) == 0) {
            snprintf(reason_buf, reason_buf_sz, "weak/default token value");
            return -1;
        }
    }

    if (len >= sizeof(lower)) {
        len = sizeof(lower) - 1;
    }
    for (i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)token[i]);
    }
    lower[len] = '\0';
    if (strstr(lower, "demo") != NULL && len < 24) {
        snprintf(reason_buf, reason_buf_sz, "token contains demo marker");
        return -1;
    }

    return 0;
}

static int validate_socks_credential_policy(const char *username, const char *password,
                                            char *reason_buf, size_t reason_buf_sz) {
    size_t ulen = 0;
    size_t plen = 0;

    if (username == NULL || password == NULL) {
        snprintf(reason_buf, reason_buf_sz, "missing username/password");
        return -1;
    }

    ulen = strlen(username);
    plen = strlen(password);
    if (ulen == 0 || ulen > 255) {
        snprintf(reason_buf, reason_buf_sz, "username length must be 1..255");
        return -1;
    }
    if (plen == 0 || plen > 255) {
        snprintf(reason_buf, reason_buf_sz, "password length must be 1..255");
        return -1;
    }
    return 0;
}

static int run_relay_cmd(int argc, char **argv) {
    endpoint_t listen_ep;
    endpoint_t target_ep;
    cli_hardening_opts_t hard_cli;
    od_hardening_options_t hard_opts;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    bool have_listen = false;
    bool have_to = false;
    bool verbose = false;
    int connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS;
    int i = 0;

    memset(&listen_ep, 0, sizeof(listen_ep));
    memset(&target_ep, 0, sizeof(target_ep));
    memset(&hard_opts, 0, sizeof(hard_opts));
    cli_hardening_init(&hard_cli);

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &listen_ep) != 0) {
                fprintf(stderr, "Invalid --listen endpoint: %s\n", argv[i + 1]);
                return 1;
            }
            have_listen = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &target_ep) != 0) {
                fprintf(stderr, "Invalid --to endpoint: %s\n", argv[i + 1]);
                return 1;
            }
            have_to = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "--connect-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 120000, &connect_timeout_ms) != 0) {
                fprintf(stderr,
                        "Invalid --connect-timeout-ms value: %s (expected 1..120000)\n",
                        argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--allow-source") == 0 && i + 1 < argc) {
            if (cli_hardening_add_allow_source(&hard_cli, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --allow-source value: %s\n", argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--rate-limit-per-min") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 100000, &hard_cli.rate_limit_per_min) != 0) {
                fprintf(stderr, "Invalid --rate-limit-per-min value: %s (expected 1..100000)\n",
                        argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-seq") == 0 && i + 1 < argc) {
            if (parse_knock_seq_arg(argv[i + 1], &hard_cli) != 0) {
                fprintf(stderr, "Invalid --knock-seq value: %s (example: 7001,7002,7003)\n",
                        argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 100, 120000, &hard_cli.knock_timeout_ms) != 0) {
                fprintf(stderr, "Invalid --knock-timeout-ms value: %s (expected 100..120000)\n",
                        argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-open-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1000, 600000, &hard_cli.knock_open_ms) != 0) {
                fprintf(stderr, "Invalid --knock-open-ms value: %s (expected 1000..600000)\n",
                        argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                cli_hardening_free(&hard_cli);
                return 1;
            }
            i++;
            continue;
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        cli_hardening_free(&hard_cli);
        return 1;
    }

    if (!have_listen || !have_to) {
        cli_hardening_free(&hard_cli);
        return 1;
    }
    if (hard_cli.knock_count > 0 && hard_cli.allow_source_count == 0) {
        fprintf(stderr, "--knock-seq requires at least one --allow-source\n");
        cli_hardening_free(&hard_cli);
        return 1;
    }

    fill_hardening_options(&hard_cli, verbose, &hard_opts);
    od_log_set_format(log_format);
    i = od_run_relay(&listen_ep, &target_ep, connect_timeout_ms, &hard_opts, verbose);
    cli_hardening_free(&hard_cli);
    return i;
}

static int run_knock_cmd(int argc, char **argv) {
    cli_knock_opts_t knock_cli;
    od_knock_plan_t plan;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    bool verbose = false;
    bool have_host = false;
    bool have_seq = false;
    int i = 0;
    int rc = 1;

    memset(&plan, 0, sizeof(plan));
    cli_knock_init(&knock_cli);

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(knock_cli.host)) {
                fprintf(stderr, "Invalid --host value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(knock_cli.host, sizeof(knock_cli.host), "%s", argv[i + 1]);
            knock_cli.have_host = true;
            have_host = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--seq") == 0 && i + 1 < argc) {
            free(knock_cli.ports);
            knock_cli.ports = NULL;
            knock_cli.port_count = 0;
            if (parse_port_seq_arg(argv[i + 1], 1, &knock_cli.ports, &knock_cli.port_count) != 0) {
                fprintf(stderr, "Invalid --seq value: %s (example: 7001,7002,7003)\n", argv[i + 1]);
                goto cleanup;
            }
            have_seq = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--delay-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 0, 120000, &knock_cli.delay_ms) != 0) {
                fprintf(stderr, "Invalid --delay-ms value: %s (expected 0..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 120000, &knock_cli.timeout_ms) != 0) {
                fprintf(stderr, "Invalid --timeout-ms value: %s (expected 1..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        goto cleanup;
    }

    if (!have_host || !have_seq) {
        goto cleanup;
    }

    plan.host = knock_cli.host;
    plan.ports = knock_cli.ports;
    plan.port_count = knock_cli.port_count;
    plan.delay_ms = knock_cli.delay_ms;
    plan.timeout_ms = knock_cli.timeout_ms;
    plan.verbose = verbose;
    od_log_set_format(log_format);
    rc = (od_run_knock(&plan) == 0) ? 0 : 1;

cleanup:
    cli_knock_free(&knock_cli);
    return rc;
}

static int send_all_text(socket_t fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(fd, buf + off, (int)(len - off), 0);
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
        return -1;
    }
    return 0;
}

static int run_admin_cmd(int argc, char **argv) {
    endpoint_t connect_ep;
    bool have_connect = false;
    bool have_token = false;
    int timeout_ms = 3000;
    char token_path[1024];
    char *token = NULL;
    const char *action = NULL;
    const char *arg = NULL;
    int i = 0;
    int rc = 1;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    socket_t fd = OD_SOCK_INVALID;
    char req[1500];
    char buf[1024];

    memset(&connect_ep, 0, sizeof(connect_ep));
    memset(token_path, 0, sizeof(token_path));
    memset(req, 0, sizeof(req));
    memset(buf, 0, sizeof(buf));

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &connect_ep) != 0) {
                fprintf(stderr, "Invalid --connect endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_connect = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--token-file") == 0 && i + 1 < argc) {
            snprintf(token_path, sizeof(token_path), "%s", argv[i + 1]);
            have_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 120000, &timeout_ms) != 0) {
                fprintf(stderr, "Invalid --timeout-ms value: %s (expected 1..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        action = argv[i];
        if (strcmp(action, "list-bind") == 0 || strcmp(action, "capabilities") == 0 ||
            strcmp(action, "status") == 0 || strcmp(action, "list-stream") == 0 ||
            strcmp(action, "route-list") == 0 || strcmp(action, "policy-show") == 0 ||
            strcmp(action, "snapshot") == 0) {
            if (i + 1 != argc) {
                fprintf(stderr, "%s does not accept extra args\n", action);
                goto cleanup;
            }
            break;
        }
        if (strcmp(action, "add-bind") == 0 || strcmp(action, "del-bind") == 0 ||
            strcmp(action, "close-stream") == 0 ||
            strcmp(action, "route-add") == 0 || strcmp(action, "route-del") == 0 ||
            strcmp(action, "policy-allow-cidr-add") == 0 || strcmp(action, "policy-allow-cidr-del") == 0 ||
            strcmp(action, "policy-allow-port-add") == 0 || strcmp(action, "policy-allow-port-del") == 0 ||
            strcmp(action, "killswitch") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s requires an argument\n", action);
                goto cleanup;
            }
            arg = argv[i + 1];
            if (i + 2 != argc) {
                fprintf(stderr, "%s accepts exactly one argument\n", action);
                goto cleanup;
            }
            break;
        }
        fprintf(stderr, "Unknown admin action: %s\n", action);
        goto cleanup;
    }

    if (!have_connect || action == NULL) {
        goto cleanup;
    }
    if (have_token) {
        token = read_token_file(token_path);
        if (token == NULL) {
            fprintf(stderr, "Invalid --token-file content\n");
            goto cleanup;
        }
    }

    if (strcmp(action, "list-bind") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tLIST_BIND\n", token);
        } else {
            snprintf(req, sizeof(req), "LIST_BIND\n");
        }
    } else if (strcmp(action, "capabilities") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tCAPABILITIES\n", token);
        } else {
            snprintf(req, sizeof(req), "CAPABILITIES\n");
        }
    } else if (strcmp(action, "status") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tSTATUS\n", token);
        } else {
            snprintf(req, sizeof(req), "STATUS\n");
        }
    } else if (strcmp(action, "list-stream") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tLIST_STREAM\n", token);
        } else {
            snprintf(req, sizeof(req), "LIST_STREAM\n");
        }
    } else if (strcmp(action, "add-bind") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tADD_BIND %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "ADD_BIND %s\n", arg);
        }
    } else if (strcmp(action, "del-bind") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tDEL_BIND %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "DEL_BIND %s\n", arg);
        }
    } else if (strcmp(action, "close-stream") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tCLOSE_STREAM %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "CLOSE_STREAM %s\n", arg);
        }
    } else if (strcmp(action, "route-list") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tROUTE_LIST\n", token);
        } else {
            snprintf(req, sizeof(req), "ROUTE_LIST\n");
        }
    } else if (strcmp(action, "route-add") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tROUTE_ADD %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "ROUTE_ADD %s\n", arg);
        }
    } else if (strcmp(action, "route-del") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tROUTE_DEL %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "ROUTE_DEL %s\n", arg);
        }
    } else if (strcmp(action, "policy-show") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tPOLICY_SHOW\n", token);
        } else {
            snprintf(req, sizeof(req), "POLICY_SHOW\n");
        }
    } else if (strcmp(action, "policy-allow-cidr-add") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tPOLICY_ALLOW_CIDR_ADD %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "POLICY_ALLOW_CIDR_ADD %s\n", arg);
        }
    } else if (strcmp(action, "policy-allow-cidr-del") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tPOLICY_ALLOW_CIDR_DEL %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "POLICY_ALLOW_CIDR_DEL %s\n", arg);
        }
    } else if (strcmp(action, "policy-allow-port-add") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tPOLICY_ALLOW_PORT_ADD %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "POLICY_ALLOW_PORT_ADD %s\n", arg);
        }
    } else if (strcmp(action, "policy-allow-port-del") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tPOLICY_ALLOW_PORT_DEL %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "POLICY_ALLOW_PORT_DEL %s\n", arg);
        }
    } else if (strcmp(action, "killswitch") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tKILLSWITCH %s\n", token, arg);
        } else {
            snprintf(req, sizeof(req), "KILLSWITCH %s\n", arg);
        }
    } else if (strcmp(action, "snapshot") == 0) {
        if (have_token) {
            snprintf(req, sizeof(req), "%s\tSNAPSHOT\n", token);
        } else {
            snprintf(req, sizeof(req), "SNAPSHOT\n");
        }
    } else {
        goto cleanup;
    }

    od_log_set_format(log_format);
    fd = od_connect_to_target(&connect_ep, timeout_ms);
    if (fd == OD_SOCK_INVALID) {
        goto cleanup;
    }
    if (send_all_text(fd, req, strlen(req)) != 0) {
        goto cleanup;
    }

    for (;;) {
        int n = recv(fd, buf, (int)(sizeof(buf) - 1), 0);
        if (n > 0) {
            buf[n] = '\0';
            fputs(buf, stdout);
            continue;
        }
        if (n == 0) {
            break;
        }
        if (od_socket_error_is_retryable(od_socket_last_error())) {
            continue;
        }
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (fd != OD_SOCK_INVALID) {
        od_socket_close(fd);
    }
    free(token);
    return rc;
}

static int run_reverse_server_cmd(int argc, char **argv) {
    endpoint_t control_ep;
    endpoint_t socks_ep;
    endpoint_t admin_ep;
    od_socks_server_opts_t socks_opts;
    od_admin_server_opts_t admin_opts;
    od_control_admin_policy_t control_admin_policy;
    cli_hardening_opts_t hard_cli;
    od_hardening_options_t hard_opts;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    od_bind_rule_t *bind_rules = NULL;
    size_t bind_count = 0;
    size_t bind_cap = 0;
    size_t max_streams = DEFAULT_MAX_STREAMS;
    bool have_control = false;
    bool have_socks = false;
    bool verbose = false;
    int heartbeat_ms = DEFAULT_HEARTBEAT_MS;
    int heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;
    od_tls_options_t tls_opts;
    char token_path[1024];
    char socks_user[256];
    char socks_pass_path[1024];
    char tls_cert_path[1024];
    char tls_key_path[1024];
    char tls_ca_path[1024];
    char admin_token_path[1024];
    char control_admin_token_path[1024];
    bool have_token = false;
    bool have_socks_user = false;
    bool have_socks_pass = false;
    bool have_tls_cert = false;
    bool have_tls_key = false;
    bool have_tls_ca = false;
    bool have_admin = false;
    bool have_admin_token = false;
    bool control_admin_enabled = true;
    bool control_admin_require_token = false;
    bool have_control_admin_token = false;
    size_t control_admin_max_binds = 256;
    int control_admin_rate_limit_per_min = 0;
    char *token = NULL;
    char *socks_pass = NULL;
    char *admin_token = NULL;
    char *control_admin_token = NULL;
    char token_policy_reason[160];
    char socks_cred_reason[160];
    int i = 0;
    int rc = 1;

    memset(&control_ep, 0, sizeof(control_ep));
    memset(&socks_ep, 0, sizeof(socks_ep));
    memset(&admin_ep, 0, sizeof(admin_ep));
    memset(&socks_opts, 0, sizeof(socks_opts));
    memset(&admin_opts, 0, sizeof(admin_opts));
    memset(&control_admin_policy, 0, sizeof(control_admin_policy));
    memset(&hard_opts, 0, sizeof(hard_opts));
    cli_hardening_init(&hard_cli);
    memset(token_path, 0, sizeof(token_path));
    memset(socks_user, 0, sizeof(socks_user));
    memset(socks_pass_path, 0, sizeof(socks_pass_path));
    memset(tls_cert_path, 0, sizeof(tls_cert_path));
    memset(tls_key_path, 0, sizeof(tls_key_path));
    memset(tls_ca_path, 0, sizeof(tls_ca_path));
    memset(admin_token_path, 0, sizeof(admin_token_path));
    memset(control_admin_token_path, 0, sizeof(control_admin_token_path));
    memset(&tls_opts, 0, sizeof(tls_opts));
    memset(token_policy_reason, 0, sizeof(token_policy_reason));
    memset(socks_cred_reason, 0, sizeof(socks_cred_reason));
    tls_opts.mode = OD_TLS_MODE_REQUIRED;
    tls_opts.require_mtls = false;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--listen-control") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &control_ep) != 0) {
                fprintf(stderr, "Invalid --listen-control endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_control = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--token-file") == 0 && i + 1 < argc) {
            snprintf(token_path, sizeof(token_path), "%s", argv[i + 1]);
            have_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            od_bind_rule_t tmp;
            od_bind_rule_t *new_rules = NULL;
            if (parse_bind_rule(argv[i + 1], &tmp) != 0) {
                fprintf(stderr, "Invalid --bind format: %s\n", argv[i + 1]);
                goto cleanup;
            }
            if (bind_count == bind_cap) {
                size_t new_cap = (bind_cap == 0) ? 4 : (bind_cap * 2);
                new_rules = (od_bind_rule_t *)realloc(bind_rules, new_cap * sizeof(*bind_rules));
                if (new_rules == NULL) {
                    fprintf(stderr, "Out of memory while parsing --bind\n");
                    goto cleanup;
                }
                bind_rules = new_rules;
                bind_cap = new_cap;
            }
            bind_rules[bind_count++] = tmp;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--socks-listen") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &socks_ep) != 0) {
                fprintf(stderr, "Invalid --socks-listen endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_socks = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--socks-user") == 0 && i + 1 < argc) {
            snprintf(socks_user, sizeof(socks_user), "%s", argv[i + 1]);
            have_socks_user = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--socks-pass-file") == 0 && i + 1 < argc) {
            snprintf(socks_pass_path, sizeof(socks_pass_path), "%s", argv[i + 1]);
            have_socks_pass = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--admin-listen") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &admin_ep) != 0) {
                fprintf(stderr, "Invalid --admin-listen endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_admin = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--admin-token-file") == 0 && i + 1 < argc) {
            snprintf(admin_token_path, sizeof(admin_token_path), "%s", argv[i + 1]);
            have_admin_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "enabled") == 0) {
                control_admin_enabled = true;
            } else if (strcmp(argv[i + 1], "disabled") == 0) {
                control_admin_enabled = false;
            } else {
                fprintf(stderr, "Invalid --control-admin value: %s (expected enabled|disabled)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-token-file") == 0 && i + 1 < argc) {
            snprintf(control_admin_token_path, sizeof(control_admin_token_path), "%s", argv[i + 1]);
            have_control_admin_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-require-token") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "enabled") == 0) {
                control_admin_require_token = true;
            } else if (strcmp(argv[i + 1], "disabled") == 0) {
                control_admin_require_token = false;
            } else {
                fprintf(stderr, "Invalid --control-admin-require-token value: %s (expected enabled|disabled)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-rate-limit-per-min") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 0, 60000, &control_admin_rate_limit_per_min) != 0) {
                fprintf(stderr,
                        "Invalid --control-admin-rate-limit-per-min value: %s (expected 0..60000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-max-binds") == 0 && i + 1 < argc) {
            int v = 0;
            if (parse_u32_arg(argv[i + 1], 1, 4096, &v) != 0) {
                fprintf(stderr, "Invalid --control-admin-max-binds value: %s (expected 1..4096)\n", argv[i + 1]);
                goto cleanup;
            }
            control_admin_max_binds = (size_t)v;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--allow-source") == 0 && i + 1 < argc) {
            if (cli_hardening_add_allow_source(&hard_cli, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --allow-source value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--rate-limit-per-min") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 100000, &hard_cli.rate_limit_per_min) != 0) {
                fprintf(stderr, "Invalid --rate-limit-per-min value: %s (expected 1..100000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-seq") == 0 && i + 1 < argc) {
            if (parse_knock_seq_arg(argv[i + 1], &hard_cli) != 0) {
                fprintf(stderr, "Invalid --knock-seq value: %s (example: 7001,7002,7003)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 100, 120000, &hard_cli.knock_timeout_ms) != 0) {
                fprintf(stderr, "Invalid --knock-timeout-ms value: %s (expected 100..120000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-open-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1000, 600000, &hard_cli.knock_open_ms) != 0) {
                fprintf(stderr, "Invalid --knock-open-ms value: %s (expected 1000..600000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-mode") == 0 && i + 1 < argc) {
            if (od_tls_parse_mode(argv[i + 1], &tls_opts.mode) != 0) {
                fprintf(stderr, "Invalid --tls-mode value: %s (expected required|disabled)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc) {
            snprintf(tls_cert_path, sizeof(tls_cert_path), "%s", argv[i + 1]);
            have_tls_cert = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc) {
            snprintf(tls_key_path, sizeof(tls_key_path), "%s", argv[i + 1]);
            have_tls_key = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-ca") == 0 && i + 1 < argc) {
            snprintf(tls_ca_path, sizeof(tls_ca_path), "%s", argv[i + 1]);
            have_tls_ca = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--require-mtls") == 0) {
            tls_opts.require_mtls = true;
            continue;
        }
        if (strcmp(argv[i], "--max-streams") == 0 && i + 1 < argc) {
            int v = 0;
            if (parse_u32_arg(argv[i + 1], 1, 4096, &v) != 0) {
                fprintf(stderr, "Invalid --max-streams value: %s (expected 1..4096)\n", argv[i + 1]);
                goto cleanup;
            }
            max_streams = (size_t)v;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--heartbeat-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 500, 120000, &heartbeat_ms) != 0) {
                fprintf(stderr, "Invalid --heartbeat-ms value: %s (expected 500..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--heartbeat-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1000, 300000, &heartbeat_timeout_ms) != 0) {
                fprintf(stderr, "Invalid --heartbeat-timeout-ms value: %s (expected 1000..300000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        goto cleanup;
    }

    if (!have_control || !have_token) {
        goto cleanup;
    }
    if (have_socks_user != have_socks_pass) {
        fprintf(stderr, "SOCKS auth requires both --socks-user and --socks-pass-file\n");
        goto cleanup;
    }
    if ((have_socks_user || have_socks_pass) && !have_socks) {
        fprintf(stderr, "SOCKS auth options require --socks-listen\n");
        goto cleanup;
    }
    if (have_admin_token && !have_admin) {
        fprintf(stderr, "--admin-token-file requires --admin-listen\n");
        goto cleanup;
    }
    if (have_control_admin_token && !control_admin_enabled) {
        fprintf(stderr, "--control-admin-token-file requires --control-admin enabled\n");
        goto cleanup;
    }
    if (control_admin_require_token && !control_admin_enabled) {
        fprintf(stderr, "--control-admin-require-token enabled requires --control-admin enabled\n");
        goto cleanup;
    }
    if (control_admin_require_token && !have_control_admin_token) {
        fprintf(stderr, "--control-admin-require-token enabled requires --control-admin-token-file\n");
        goto cleanup;
    }
    if (heartbeat_timeout_ms <= heartbeat_ms) {
        fprintf(stderr, "--heartbeat-timeout-ms must be greater than --heartbeat-ms\n");
        goto cleanup;
    }
    if (hard_cli.knock_count > 0 && hard_cli.allow_source_count == 0) {
        fprintf(stderr, "--knock-seq requires at least one --allow-source\n");
        goto cleanup;
    }
    if (tls_opts.mode == OD_TLS_MODE_REQUIRED) {
        if (!have_tls_cert || !have_tls_key) {
            fprintf(stderr, "TLS required: provide --tls-cert and --tls-key (or use --tls-mode disabled)\n");
            goto cleanup;
        }
        if (tls_opts.require_mtls && !have_tls_ca) {
            fprintf(stderr, "mTLS requires --tls-ca\n");
            goto cleanup;
        }
    } else if (tls_opts.require_mtls) {
        fprintf(stderr, "--require-mtls only valid with --tls-mode required\n");
        goto cleanup;
    }

    token = read_token_file(token_path);
    if (token == NULL) {
        fprintf(stderr, "Invalid token file content\n");
        goto cleanup;
    }
    if (validate_token_policy(token, token_policy_reason, sizeof(token_policy_reason)) != 0) {
        fprintf(stderr, "Token policy error: %s\n", token_policy_reason);
        goto cleanup;
    }
    if (have_socks_pass) {
        socks_pass = read_token_file(socks_pass_path);
        if (socks_pass == NULL) {
            fprintf(stderr, "Invalid --socks-pass-file content\n");
            goto cleanup;
        }
        if (validate_socks_credential_policy(socks_user, socks_pass,
                                             socks_cred_reason, sizeof(socks_cred_reason)) != 0) {
            fprintf(stderr, "SOCKS credential policy error: %s\n", socks_cred_reason);
            goto cleanup;
        }
    }
    if (have_admin_token) {
        admin_token = read_token_file(admin_token_path);
        if (admin_token == NULL) {
            fprintf(stderr, "Invalid --admin-token-file content\n");
            goto cleanup;
        }
    }
    if (have_control_admin_token) {
        control_admin_token = read_token_file(control_admin_token_path);
        if (control_admin_token == NULL) {
            fprintf(stderr, "Invalid --control-admin-token-file content\n");
            goto cleanup;
        }
    }

    tls_opts.cert_file = have_tls_cert ? tls_cert_path : NULL;
    tls_opts.key_file = have_tls_key ? tls_key_path : NULL;
    tls_opts.ca_file = have_tls_ca ? tls_ca_path : NULL;
    tls_opts.server_name = NULL;

    memset(&socks_opts, 0, sizeof(socks_opts));
    socks_opts.listen_ep = have_socks ? &socks_ep : NULL;
    socks_opts.username = have_socks_user ? socks_user : NULL;
    socks_opts.password = have_socks_pass ? socks_pass : NULL;
    memset(&admin_opts, 0, sizeof(admin_opts));
    admin_opts.listen_ep = have_admin ? &admin_ep : NULL;
    admin_opts.token = have_admin_token ? admin_token : NULL;
    memset(&control_admin_policy, 0, sizeof(control_admin_policy));
    control_admin_policy.enabled = control_admin_enabled;
    control_admin_policy.require_token = control_admin_require_token;
    control_admin_policy.token = have_control_admin_token ? control_admin_token : NULL;
    control_admin_policy.max_binds = control_admin_max_binds;
    control_admin_policy.rate_limit_per_min = control_admin_rate_limit_per_min;
    fill_hardening_options(&hard_cli, verbose, &hard_opts);
    od_log_set_format(log_format);

    rc = od_run_reverse_server(&control_ep, bind_rules, bind_count,
                               socks_opts.listen_ep != NULL ? &socks_opts : NULL,
                               max_streams, token,
                               &hard_opts,
                               admin_opts.listen_ep != NULL ? &admin_opts : NULL,
                               &control_admin_policy,
                               &tls_opts,
                               heartbeat_ms, heartbeat_timeout_ms, verbose);

cleanup:
    free(control_admin_token);
    free(admin_token);
    free(socks_pass);
    free(token);
    free(bind_rules);
    cli_hardening_free(&hard_cli);
    return rc;
}

static int run_gateway_cmd(int argc, char **argv) {
    endpoint_t control_ep;
    endpoint_t admin_ep;
    cli_string_list_t route_allow;
    od_gateway_run_opts_t gateway_opts;
    od_tun_gateway_opts_t tun_opts;
    od_tun_error_t tun_err;
    od_hardening_options_t hard_opts;
    od_tls_options_t tls_opts;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    bool have_control = false;
    bool have_token = false;
    bool have_tun_name = false;
    bool have_tun_cidr = false;
    bool have_admin = false;
    bool have_admin_token = false;
    bool have_tls_cert = false;
    bool have_tls_key = false;
    bool have_tls_ca = false;
    bool control_admin_enabled = true;
    bool control_admin_require_token = false;
    bool have_control_admin_token = false;
    bool verbose = false;
    int gateway_mtu = OD_TUN_DEFAULT_MTU;
    int heartbeat_ms = DEFAULT_HEARTBEAT_MS;
    int heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;
    int control_admin_rate_limit_per_min = 0;
    char token_path[1024];
    char tun_name[128];
    char tun_cidr[64];
    char tls_cert_path[1024];
    char tls_key_path[1024];
    char tls_ca_path[1024];
    char admin_token_path[1024];
    char control_admin_token_path[1024];
    char *token = NULL;
    char *admin_token = NULL;
    char *control_admin_token = NULL;
    char token_policy_reason[160];
    int i = 0;
    int rc = 1;

    memset(&control_ep, 0, sizeof(control_ep));
    memset(&admin_ep, 0, sizeof(admin_ep));
    memset(&route_allow, 0, sizeof(route_allow));
    memset(&gateway_opts, 0, sizeof(gateway_opts));
    memset(&tun_opts, 0, sizeof(tun_opts));
    memset(&tun_err, 0, sizeof(tun_err));
    memset(&hard_opts, 0, sizeof(hard_opts));
    memset(&tls_opts, 0, sizeof(tls_opts));
    memset(token_path, 0, sizeof(token_path));
    memset(tun_name, 0, sizeof(tun_name));
    memset(tun_cidr, 0, sizeof(tun_cidr));
    memset(tls_cert_path, 0, sizeof(tls_cert_path));
    memset(tls_key_path, 0, sizeof(tls_key_path));
    memset(tls_ca_path, 0, sizeof(tls_ca_path));
    memset(admin_token_path, 0, sizeof(admin_token_path));
    memset(control_admin_token_path, 0, sizeof(control_admin_token_path));
    memset(token_policy_reason, 0, sizeof(token_policy_reason));
    tls_opts.mode = OD_TLS_MODE_REQUIRED;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--listen-control") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &control_ep) != 0) {
                fprintf(stderr, "Invalid --listen-control endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_control = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--token-file") == 0 && i + 1 < argc) {
            snprintf(token_path, sizeof(token_path), "%s", argv[i + 1]);
            have_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tun-name") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(tun_name)) {
                fprintf(stderr, "Invalid --tun-name value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(tun_name, sizeof(tun_name), "%s", argv[i + 1]);
            have_tun_name = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tun-cidr") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(tun_cidr)) {
                fprintf(stderr, "Invalid --tun-cidr value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(tun_cidr, sizeof(tun_cidr), "%s", argv[i + 1]);
            have_tun_cidr = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--route-allow") == 0 && i + 1 < argc) {
            if (cli_string_list_add(&route_allow, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --route-allow value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--gateway-mtu") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], OD_TUN_MTU_MIN, OD_TUN_MTU_MAX, &gateway_mtu) != 0) {
                fprintf(stderr, "Invalid --gateway-mtu value: %s (expected %d..%d)\n",
                        argv[i + 1], OD_TUN_MTU_MIN, OD_TUN_MTU_MAX);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--admin-listen") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &admin_ep) != 0) {
                fprintf(stderr, "Invalid --admin-listen endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_admin = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--admin-token-file") == 0 && i + 1 < argc) {
            snprintf(admin_token_path, sizeof(admin_token_path), "%s", argv[i + 1]);
            have_admin_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "enabled") == 0) {
                control_admin_enabled = true;
            } else if (strcmp(argv[i + 1], "disabled") == 0) {
                control_admin_enabled = false;
            } else {
                fprintf(stderr, "Invalid --control-admin value: %s (expected enabled|disabled)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-token-file") == 0 && i + 1 < argc) {
            snprintf(control_admin_token_path, sizeof(control_admin_token_path), "%s", argv[i + 1]);
            have_control_admin_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-require-token") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "enabled") == 0) {
                control_admin_require_token = true;
            } else if (strcmp(argv[i + 1], "disabled") == 0) {
                control_admin_require_token = false;
            } else {
                fprintf(stderr, "Invalid --control-admin-require-token value: %s (expected enabled|disabled)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--control-admin-rate-limit-per-min") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 0, 60000, &control_admin_rate_limit_per_min) != 0) {
                fprintf(stderr,
                        "Invalid --control-admin-rate-limit-per-min value: %s (expected 0..60000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-mode") == 0 && i + 1 < argc) {
            if (od_tls_parse_mode(argv[i + 1], &tls_opts.mode) != 0) {
                fprintf(stderr, "Invalid --tls-mode value: %s (expected required|disabled)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc) {
            snprintf(tls_cert_path, sizeof(tls_cert_path), "%s", argv[i + 1]);
            have_tls_cert = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc) {
            snprintf(tls_key_path, sizeof(tls_key_path), "%s", argv[i + 1]);
            have_tls_key = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-ca") == 0 && i + 1 < argc) {
            snprintf(tls_ca_path, sizeof(tls_ca_path), "%s", argv[i + 1]);
            have_tls_ca = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--heartbeat-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 500, 120000, &heartbeat_ms) != 0) {
                fprintf(stderr, "Invalid --heartbeat-ms value: %s (expected 500..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--heartbeat-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1000, 300000, &heartbeat_timeout_ms) != 0) {
                fprintf(stderr, "Invalid --heartbeat-timeout-ms value: %s (expected 1000..300000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        goto cleanup;
    }

    if (!have_control || !have_token || !have_tun_name || !have_tun_cidr) {
        goto cleanup;
    }
    if (have_control_admin_token && !control_admin_enabled) {
        fprintf(stderr, "--control-admin-token-file requires --control-admin enabled\n");
        goto cleanup;
    }
    if (have_admin_token && !have_admin) {
        fprintf(stderr, "--admin-token-file requires --admin-listen\n");
        goto cleanup;
    }
    if (control_admin_require_token && !control_admin_enabled) {
        fprintf(stderr, "--control-admin-require-token enabled requires --control-admin enabled\n");
        goto cleanup;
    }
    if (control_admin_require_token && !have_control_admin_token) {
        fprintf(stderr, "--control-admin-require-token enabled requires --control-admin-token-file\n");
        goto cleanup;
    }
    if (heartbeat_timeout_ms <= heartbeat_ms) {
        fprintf(stderr, "--heartbeat-timeout-ms must be greater than --heartbeat-ms\n");
        goto cleanup;
    }
    if (tls_opts.mode == OD_TLS_MODE_REQUIRED) {
        if (!have_tls_cert || !have_tls_key) {
            fprintf(stderr, "TLS required: provide --tls-cert and --tls-key (or use --tls-mode disabled)\n");
            goto cleanup;
        }
    }
    tun_opts.tun_name = have_tun_name ? tun_name : NULL;
    tun_opts.tun_cidr = have_tun_cidr ? tun_cidr : NULL;
    tun_opts.gateway_mtu = gateway_mtu;
    tun_opts.route_allow = (const char *const *)route_allow.items;
    tun_opts.route_allow_count = route_allow.count;
    if (od_tun_validate_gateway_opts(&tun_opts, &tun_err) != 0) {
        fprintf(stderr, "TUN policy error: %s\n", tun_err.message);
        goto cleanup;
    }

    token = read_token_file(token_path);
    if (token == NULL) {
        fprintf(stderr, "Invalid token file content\n");
        goto cleanup;
    }
    if (validate_token_policy(token, token_policy_reason, sizeof(token_policy_reason)) != 0) {
        fprintf(stderr, "Token policy error: %s\n", token_policy_reason);
        goto cleanup;
    }
    if (have_control_admin_token) {
        control_admin_token = read_token_file(control_admin_token_path);
        if (control_admin_token == NULL) {
            fprintf(stderr, "Invalid --control-admin-token-file content\n");
            goto cleanup;
        }
        if (validate_token_policy(control_admin_token, token_policy_reason, sizeof(token_policy_reason)) != 0) {
            fprintf(stderr, "Control-admin token policy error: %s\n", token_policy_reason);
            goto cleanup;
        }
    }
    if (have_admin_token) {
        admin_token = read_token_file(admin_token_path);
        if (admin_token == NULL) {
            fprintf(stderr, "Invalid --admin-token-file content\n");
            goto cleanup;
        }
        if (validate_token_policy(admin_token, token_policy_reason, sizeof(token_policy_reason)) != 0) {
            fprintf(stderr, "Admin token policy error: %s\n", token_policy_reason);
            goto cleanup;
        }
    }

    tls_opts.cert_file = have_tls_cert ? tls_cert_path : NULL;
    tls_opts.key_file = have_tls_key ? tls_key_path : NULL;
    tls_opts.ca_file = have_tls_ca ? tls_ca_path : NULL;
    tls_opts.server_name = NULL;
    od_log_set_format(log_format);
    memset(&gateway_opts, 0, sizeof(gateway_opts));
    gateway_opts.control_listen_ep = control_ep;
    gateway_opts.token = token;
    gateway_opts.tun_opts = tun_opts;
    gateway_opts.hardening_opts = hard_opts;
    gateway_opts.tls_opts = tls_opts;
    gateway_opts.admin_listen_ep = have_admin ? &admin_ep : NULL;
    gateway_opts.admin_token = have_admin_token ? admin_token : NULL;
    gateway_opts.control_admin_enabled = control_admin_enabled;
    gateway_opts.control_admin_require_token = control_admin_require_token;
    gateway_opts.control_admin_token = have_control_admin_token ? control_admin_token : NULL;
    gateway_opts.control_admin_rate_limit_per_min = control_admin_rate_limit_per_min;
    gateway_opts.heartbeat_ms = heartbeat_ms;
    gateway_opts.heartbeat_timeout_ms = heartbeat_timeout_ms;
    gateway_opts.verbose = verbose;
    rc = od_run_gateway(&gateway_opts);

cleanup:
    free(control_admin_token);
    free(admin_token);
    free(token);
    cli_string_list_free(&route_allow);
    return rc;
}

static int run_reverse_client_cmd(int argc, char **argv) {
    endpoint_t connect_ep;
    cli_knock_opts_t knock_cli;
    cli_string_list_t tun_allow_cidrs;
    cli_string_list_t tun_allow_ports;
    od_tun_agent_opts_t tun_agent_opts;
    od_tun_agent_runtime_opts_t tun_runtime_opts;
    od_tun_policy_t tun_policy;
    od_tun_error_t tun_err;
    od_knock_plan_t knock_plan;
    const od_knock_plan_t *knock_plan_ptr = NULL;
    od_ctrl_action_t *ctrl_actions = NULL;
    size_t ctrl_action_count = 0;
    size_t ctrl_action_cap = 0;
    od_ctrl_client_opts_t ctrl_opts;
    bool ctl_exit_after_admin = false;
    const od_ctrl_client_opts_t *ctrl_opts_ptr = NULL;
    endpoint_t *allow_targets = NULL;
    size_t allow_count = 0;
    size_t allow_cap = 0;
    size_t max_streams = DEFAULT_MAX_STREAMS;
    bool have_connect = false;
    bool verbose = false;
    od_log_format_t log_format = OD_LOG_FORMAT_TEXT;
    int connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS;
    int heartbeat_timeout_ms = DEFAULT_HEARTBEAT_TIMEOUT_MS;
    od_tls_options_t tls_opts;
    char token_path[1024];
    char tls_ca_path[1024];
    char tls_server_name[256];
    char tls_cert_path[1024];
    char tls_key_path[1024];
    char ctl_token_path[1024];
    bool have_token = false;
    bool have_tls_ca = false;
    bool have_tls_server_name = false;
    bool have_tls_cert = false;
    bool have_tls_key = false;
    bool have_ctl_token = false;
    bool tun_mode = false;
    bool have_mode = false;
    bool have_tun_agent_name = false;
    char tun_agent_name[128];
    bool have_agent_tun_cidr = false;
    char agent_tun_cidr[64];
    char *token = NULL;
    char *ctl_token = NULL;
    char token_policy_reason[160];
    int i = 0;
    int rc = 1;

    memset(&connect_ep, 0, sizeof(connect_ep));
    memset(&tun_allow_cidrs, 0, sizeof(tun_allow_cidrs));
    memset(&tun_allow_ports, 0, sizeof(tun_allow_ports));
    memset(&tun_agent_opts, 0, sizeof(tun_agent_opts));
    memset(&tun_runtime_opts, 0, sizeof(tun_runtime_opts));
    memset(&tun_policy, 0, sizeof(tun_policy));
    memset(&tun_err, 0, sizeof(tun_err));
    memset(&knock_plan, 0, sizeof(knock_plan));
    memset(&ctrl_opts, 0, sizeof(ctrl_opts));
    cli_knock_init(&knock_cli);
    memset(token_path, 0, sizeof(token_path));
    memset(tls_ca_path, 0, sizeof(tls_ca_path));
    memset(tls_server_name, 0, sizeof(tls_server_name));
    memset(tls_cert_path, 0, sizeof(tls_cert_path));
    memset(tls_key_path, 0, sizeof(tls_key_path));
    memset(ctl_token_path, 0, sizeof(ctl_token_path));
    memset(tun_agent_name, 0, sizeof(tun_agent_name));
    memset(agent_tun_cidr, 0, sizeof(agent_tun_cidr));
    memset(&tls_opts, 0, sizeof(tls_opts));
    memset(token_policy_reason, 0, sizeof(token_policy_reason));
    tls_opts.mode = OD_TLS_MODE_REQUIRED;
    tls_opts.require_mtls = false;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "reverse") == 0) {
                tun_mode = false;
            } else if (strcmp(argv[i + 1], "tun-agent") == 0) {
                tun_mode = true;
            } else {
                fprintf(stderr, "Invalid --mode value: %s (expected reverse|tun-agent)\n", argv[i + 1]);
                goto cleanup;
            }
            have_mode = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            if (parse_endpoint(argv[i + 1], &connect_ep) != 0) {
                fprintf(stderr, "Invalid --connect endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            have_connect = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--token-file") == 0 && i + 1 < argc) {
            snprintf(token_path, sizeof(token_path), "%s", argv[i + 1]);
            have_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--allow-target") == 0 && i + 1 < argc) {
            endpoint_t ep;
            endpoint_t *new_targets = NULL;
            memset(&ep, 0, sizeof(ep));
            if (parse_endpoint(argv[i + 1], &ep) != 0) {
                fprintf(stderr, "Invalid --allow-target endpoint: %s\n", argv[i + 1]);
                goto cleanup;
            }
            if (allow_count == allow_cap) {
                size_t new_cap = (allow_cap == 0) ? 8 : (allow_cap * 2);
                new_targets = (endpoint_t *)realloc(allow_targets, new_cap * sizeof(*allow_targets));
                if (new_targets == NULL) {
                    fprintf(stderr, "Out of memory while parsing --allow-target\n");
                    goto cleanup;
                }
                allow_targets = new_targets;
                allow_cap = new_cap;
            }
            allow_targets[allow_count++] = ep;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--allow-cidr") == 0 && i + 1 < argc) {
            if (cli_string_list_add(&tun_allow_cidrs, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --allow-cidr value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--allow-port") == 0 && i + 1 < argc) {
            if (cli_string_list_add(&tun_allow_ports, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --allow-port value: %s (expected tcp:PORT|udp:PORT)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--agent-name") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(tun_agent_name)) {
                fprintf(stderr, "Invalid --agent-name value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(tun_agent_name, sizeof(tun_agent_name), "%s", argv[i + 1]);
            have_tun_agent_name = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--agent-tun-cidr") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(agent_tun_cidr) ||
                strchr(argv[i + 1], '/') == NULL) {
                fprintf(stderr, "Invalid --agent-tun-cidr value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(agent_tun_cidr, sizeof(agent_tun_cidr), "%s", argv[i + 1]);
            have_agent_tun_cidr = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-before-connect") == 0) {
            knock_cli.enabled = true;
            continue;
        }
        if (strcmp(argv[i], "--knock-host") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) >= sizeof(knock_cli.host)) {
                fprintf(stderr, "Invalid --knock-host value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            snprintf(knock_cli.host, sizeof(knock_cli.host), "%s", argv[i + 1]);
            knock_cli.have_host = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-seq") == 0 && i + 1 < argc) {
            free(knock_cli.ports);
            knock_cli.ports = NULL;
            knock_cli.port_count = 0;
            if (parse_port_seq_arg(argv[i + 1], 1, &knock_cli.ports, &knock_cli.port_count) != 0) {
                fprintf(stderr, "Invalid --knock-seq value: %s (example: 7001,7002,7003)\n", argv[i + 1]);
                goto cleanup;
            }
            knock_cli.enabled = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-delay-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 0, 120000, &knock_cli.delay_ms) != 0) {
                fprintf(stderr, "Invalid --knock-delay-ms value: %s (expected 0..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--knock-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 120000, &knock_cli.timeout_ms) != 0) {
                fprintf(stderr, "Invalid --knock-timeout-ms value: %s (expected 1..120000)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-list-bind") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_LIST_BIND, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-list-bind\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-add-bind") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_ADD_BIND, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-add-bind value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-del-bind") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_DEL_BIND, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-del-bind value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-capabilities") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_CAPABILITIES, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-capabilities\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-status") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_STATUS, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-status\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-list-stream") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_LIST_STREAM, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-list-stream\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-close-stream") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_CLOSE_STREAM, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-close-stream value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-route-list") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_ROUTE_LIST, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-route-list\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-route-add") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_ROUTE_ADD, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-route-add value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-route-del") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_ROUTE_DEL, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-route-del value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-policy-show") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_POLICY_SHOW, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-policy-show\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-policy-allow-cidr-add") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_ADD, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-policy-allow-cidr-add value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-policy-allow-cidr-del") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_DEL, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-policy-allow-cidr-del value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-policy-allow-port-add") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_ADD, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-policy-allow-port-add value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-policy-allow-port-del") == 0 && i + 1 < argc) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_DEL, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid/too long --ctl-policy-allow-port-del value: %s\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-killswitch") == 0 && i + 1 < argc) {
            if ((strcmp(argv[i + 1], "on") != 0 && strcmp(argv[i + 1], "off") != 0) ||
                ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_TUN_KILLSWITCH, argv[i + 1]) != 0) {
                fprintf(stderr, "Invalid --ctl-killswitch value: %s (expected on|off)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--ctl-snapshot") == 0) {
            if (ctrl_action_add(&ctrl_actions, &ctrl_action_count, &ctrl_action_cap,
                                OD_CTRL_ACTION_SNAPSHOT, NULL) != 0) {
                fprintf(stderr, "Out of memory while parsing --ctl-snapshot\n");
                goto cleanup;
            }
            continue;
        }
        if (strcmp(argv[i], "--ctl-exit-after-admin") == 0) {
            ctl_exit_after_admin = true;
            continue;
        }
        if (strcmp(argv[i], "--ctl-token-file") == 0 && i + 1 < argc) {
            snprintf(ctl_token_path, sizeof(ctl_token_path), "%s", argv[i + 1]);
            have_ctl_token = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-mode") == 0 && i + 1 < argc) {
            if (od_tls_parse_mode(argv[i + 1], &tls_opts.mode) != 0) {
                fprintf(stderr, "Invalid --tls-mode value: %s (expected required|disabled)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-ca") == 0 && i + 1 < argc) {
            snprintf(tls_ca_path, sizeof(tls_ca_path), "%s", argv[i + 1]);
            have_tls_ca = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-server-name") == 0 && i + 1 < argc) {
            snprintf(tls_server_name, sizeof(tls_server_name), "%s", argv[i + 1]);
            have_tls_server_name = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-cert") == 0 && i + 1 < argc) {
            snprintf(tls_cert_path, sizeof(tls_cert_path), "%s", argv[i + 1]);
            have_tls_cert = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--tls-key") == 0 && i + 1 < argc) {
            snprintf(tls_key_path, sizeof(tls_key_path), "%s", argv[i + 1]);
            have_tls_key = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--max-streams") == 0 && i + 1 < argc) {
            int v = 0;
            if (parse_u32_arg(argv[i + 1], 1, 4096, &v) != 0) {
                fprintf(stderr, "Invalid --max-streams value: %s (expected 1..4096)\n", argv[i + 1]);
                goto cleanup;
            }
            max_streams = (size_t)v;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--connect-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1, 120000, &connect_timeout_ms) != 0) {
                fprintf(stderr,
                        "Invalid --connect-timeout-ms value: %s (expected 1..120000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--heartbeat-timeout-ms") == 0 && i + 1 < argc) {
            if (parse_u32_arg(argv[i + 1], 1000, 300000, &heartbeat_timeout_ms) != 0) {
                fprintf(stderr, "Invalid --heartbeat-timeout-ms value: %s (expected 1000..300000)\n",
                        argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(argv[i], "--log-format") == 0 && i + 1 < argc) {
            if (parse_log_format_arg(argv[i + 1], &log_format) != 0) {
                fprintf(stderr, "Invalid --log-format value: %s (expected text|json)\n", argv[i + 1]);
                goto cleanup;
            }
            i++;
            continue;
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        goto cleanup;
    }

    if (!have_mode) {
        tun_mode = false;
    }
    if (!have_connect || !have_token) {
        goto cleanup;
    }
    if (tun_mode) {
        if (allow_count > 0) {
            fprintf(stderr, "--allow-target is only valid for --mode reverse\n");
            goto cleanup;
        }
        if (ctrl_action_count > 0 || have_ctl_token || ctl_exit_after_admin) {
            fprintf(stderr, "--ctl-* options are only valid for --mode reverse\n");
            goto cleanup;
        }
        tun_agent_opts.agent_name = have_tun_agent_name ? tun_agent_name : NULL;
        tun_agent_opts.allow_cidrs = (const char *const *)tun_allow_cidrs.items;
        tun_agent_opts.allow_cidr_count = tun_allow_cidrs.count;
        tun_agent_opts.allow_ports = (const char *const *)tun_allow_ports.items;
        tun_agent_opts.allow_port_count = tun_allow_ports.count;
        if (od_tun_validate_agent_opts(&tun_agent_opts, &tun_err) != 0) {
            fprintf(stderr, "TUN policy error: %s\n", tun_err.message);
            goto cleanup;
        }
        od_tun_build_policy_from_agent_opts(&tun_agent_opts, &tun_policy);
    } else {
        if (tun_allow_cidrs.count > 0 || tun_allow_ports.count > 0 || have_tun_agent_name || have_agent_tun_cidr) {
            fprintf(stderr, "--allow-cidr/--allow-port/--agent-name/--agent-tun-cidr require --mode tun-agent\n");
            goto cleanup;
        }
        if (ctl_exit_after_admin && ctrl_action_count == 0) {
            fprintf(stderr, "--ctl-exit-after-admin requires at least one --ctl-* action\n");
            goto cleanup;
        }
        if (have_ctl_token && ctrl_action_count == 0) {
            fprintf(stderr, "--ctl-token-file requires at least one --ctl-* action\n");
            goto cleanup;
        }
    }
    if (knock_cli.enabled && knock_cli.port_count == 0) {
        fprintf(stderr, "--knock-before-connect requires --knock-seq\n");
        goto cleanup;
    }
    if (knock_cli.enabled && !knock_cli.have_host) {
        snprintf(knock_cli.host, sizeof(knock_cli.host), "%s", connect_ep.host);
        knock_cli.have_host = true;
    }
    if (tls_opts.mode == OD_TLS_MODE_REQUIRED) {
        if (!have_tls_ca) {
            fprintf(stderr, "TLS required: provide --tls-ca (or use --tls-mode disabled)\n");
            goto cleanup;
        }
    }
    if (have_tls_cert ^ have_tls_key) {
        fprintf(stderr, "Client mTLS requires both --tls-cert and --tls-key\n");
        goto cleanup;
    }

    token = read_token_file(token_path);
    if (token == NULL) {
        fprintf(stderr, "Invalid token file content\n");
        goto cleanup;
    }
    if (have_ctl_token) {
        ctl_token = read_token_file(ctl_token_path);
        if (ctl_token == NULL) {
            fprintf(stderr, "Invalid --ctl-token-file content\n");
            goto cleanup;
        }
    }
    if (validate_token_policy(token, token_policy_reason, sizeof(token_policy_reason)) != 0) {
        fprintf(stderr, "Token policy error: %s\n", token_policy_reason);
        goto cleanup;
    }

    tls_opts.ca_file = have_tls_ca ? tls_ca_path : NULL;
    tls_opts.cert_file = have_tls_cert ? tls_cert_path : NULL;
    tls_opts.key_file = have_tls_key ? tls_key_path : NULL;
    tls_opts.server_name = have_tls_server_name ? tls_server_name : connect_ep.host;
    od_log_set_format(log_format);
    if (tun_mode) {
        tun_runtime_opts.agent_name = have_tun_agent_name ? tun_agent_name : NULL;
        tun_runtime_opts.allow_cidrs = (const char *const *)tun_allow_cidrs.items;
        tun_runtime_opts.allow_cidr_count = tun_allow_cidrs.count;
        tun_runtime_opts.allow_ports = (const char *const *)tun_allow_ports.items;
        tun_runtime_opts.allow_port_count = tun_allow_ports.count;
        tun_runtime_opts.agent_tun_cidr = have_agent_tun_cidr ? agent_tun_cidr : NULL;
        tun_runtime_opts.agent_tun_name = NULL;
        tun_runtime_opts.agent_tun_mtu = 0;
        od_log_info("reverse-client tun-agent runtime connect=%s:%u allow-cidr=%lu allow-port=%lu tls=%s",
                    connect_ep.host, (unsigned)connect_ep.port,
                    (unsigned long)tun_policy.allow_cidr_count, (unsigned long)tun_policy.allow_port_count,
                    od_tls_mode_name(tls_opts.mode));
        od_log_info("reverse-client tun-agent policy default-deny=%s",
                    od_tun_policy_is_default_deny(&tun_policy) ? "true" : "false");
        if (have_tun_agent_name) {
            od_log_info("reverse-client tun-agent name=%s", tun_agent_name);
        }
        if (have_agent_tun_cidr) {
            od_log_info("reverse-client tun-agent L3 dataplane cidr=%s", agent_tun_cidr);
        }
        rc = od_run_tun_agent(&connect_ep, token, &tun_runtime_opts,
                              connect_timeout_ms, knock_plan_ptr,
                              &tls_opts, heartbeat_timeout_ms, verbose);
        goto cleanup;
    }

    if (knock_cli.enabled) {
        memset(&knock_plan, 0, sizeof(knock_plan));
        knock_plan.host = knock_cli.host;
        knock_plan.ports = knock_cli.ports;
        knock_plan.port_count = knock_cli.port_count;
        knock_plan.delay_ms = knock_cli.delay_ms;
        knock_plan.timeout_ms = knock_cli.timeout_ms;
        knock_plan.verbose = verbose;
        knock_plan_ptr = &knock_plan;
    }
    if (ctrl_action_count > 0) {
        ctrl_opts.actions = ctrl_actions;
        ctrl_opts.action_count = ctrl_action_count;
        ctrl_opts.exit_after_actions = ctl_exit_after_admin;
        ctrl_opts.admin_token = have_ctl_token ? ctl_token : NULL;
        ctrl_opts_ptr = &ctrl_opts;
    }

    rc = od_run_reverse_client(&connect_ep, allow_targets, allow_count, max_streams, token,
                               connect_timeout_ms, knock_plan_ptr, ctrl_opts_ptr, &tls_opts,
                               heartbeat_timeout_ms, verbose);

cleanup:
    free(ctrl_actions);
    free(ctl_token);
    free(token);
    free(allow_targets);
    cli_string_list_free(&tun_allow_ports);
    cli_string_list_free(&tun_allow_cidrs);
    cli_knock_free(&knock_cli);
    return rc;
}

int main(int argc, char **argv) {
    int rc = 1;

    if (od_socket_init() != 0) {
        return 1;
    }
    if (od_tls_global_init() != 0) {
        od_socket_cleanup();
        return 1;
    }

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#endif

    if (argc < 2) {
        print_usage(argv[0]);
        od_tls_global_cleanup();
        od_socket_cleanup();
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
        print_version();
        od_tls_global_cleanup();
        od_socket_cleanup();
        return 0;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        od_tls_global_cleanup();
        od_socket_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "relay") == 0) {
        rc = run_relay_cmd(argc, argv);
    } else if (strcmp(argv[1], "knock") == 0) {
        rc = run_knock_cmd(argc, argv);
    } else if (strcmp(argv[1], "admin") == 0) {
        rc = run_admin_cmd(argc, argv);
    } else if (strcmp(argv[1], "reverse-server") == 0) {
        rc = run_reverse_server_cmd(argc, argv);
    } else if (strcmp(argv[1], "gateway") == 0) {
        rc = run_gateway_cmd(argc, argv);
    } else if (strcmp(argv[1], "reverse-client") == 0) {
        rc = run_reverse_client_cmd(argc, argv);
    } else {
        print_usage(argv[0]);
        od_tls_global_cleanup();
        od_socket_cleanup();
        return 1;
    }

    if (rc != 0) {
        print_usage(argv[0]);
    }

    od_tls_global_cleanup();
    od_socket_cleanup();
    return rc;
}
