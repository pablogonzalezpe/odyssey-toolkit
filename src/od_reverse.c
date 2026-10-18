#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#endif

#include "od_log.h"
#include "od_proto.h"
#include "od_reverse.h"
#include "od_socks.h"
#include "od_socket.h"
#include "od_tls.h"
#include "od_tun_dev.h"

#define DEFAULT_POLL_MS 250
#define FORWARD_BUF_SIZE 8192
#define HELLO_TEXT "odyssey/1"
#define POLL_KIND_CONTROL 1
#define POLL_KIND_LISTENER 2
#define POLL_KIND_STREAM 3
#define POLL_KIND_SOCKS_LISTENER 4
#define POLL_KIND_KNOCK_LISTENER 5
#define POLL_KIND_ADMIN_LISTENER 6
#define POLL_KIND_TUN_DEV 7

typedef struct {
    int heartbeat_ms;
    int heartbeat_timeout_ms;
    bool verbose;
    uint64_t last_rx_ms;
    uint64_t last_ping_ms;
} hb_state_t;

typedef struct {
    int kind;
    size_t idx;
} poll_meta_t;

typedef struct {
    socket_t lfd;
    uint16_t port;
    bool active;
} knock_listener_t;

typedef struct {
    bool present;
    uint32_t bind_id;
    endpoint_t listen_ep;
    endpoint_t target_ep;
    socket_t lfd;
    bool active;
} srv_bind_t;

typedef struct {
    srv_bind_t *items;
    size_t count;
    size_t cap;
    uint32_t next_bind_id;
} srv_bind_manager_t;

typedef struct {
    bool used;
    bool open_confirmed;
    bool is_socks;
    bool socks_reply_sent;
    uint32_t stream_id;
    socket_t local_fd;
    endpoint_t target;
    uint64_t bytes_from_local;
    uint64_t bytes_to_local;
} srv_stream_t;

typedef struct {
    bool used;
    uint32_t stream_id;
    socket_t target_fd;
    endpoint_t target;
    uint64_t bytes_from_target;
    uint64_t bytes_to_target;
} cli_stream_t;

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} runtime_string_list_t;

typedef struct {
    bool known;
    runtime_string_list_t allow_cidrs;
    runtime_string_list_t allow_ports;
} tun_policy_cache_t;

typedef struct {
    bool active;
    int tun_fd;
    bool control_connected;
    bool policy_dirty;
    bool killswitch_manual;
    runtime_string_list_t route_allow;
    tun_policy_cache_t policy;
    uint64_t pkts_from_tun;
    uint64_t pkts_to_tun;
    uint64_t bytes_from_tun;
    uint64_t bytes_to_tun;
    uint64_t drops_from_tun;
    uint64_t drops_to_tun;
} tun_gateway_ctx_t;

typedef struct {
    uint64_t pkts_in;
    uint64_t pkts_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t drops_policy;
    uint64_t drops_parse;
} tun_agent_stats_t;

static int append_line(char *out, size_t out_sz, size_t *used, const char *line);
static int appendf_line(char *out, size_t out_sz, size_t *used, const char *fmt, ...);

static tun_gateway_ctx_t g_tun_gateway_ctx = {false, -1, false, false, false, {NULL, 0, 0},
                                              {false, {NULL, 0, 0}, {NULL, 0, 0}},
                                              0, 0, 0, 0, 0, 0};

static void runtime_string_list_free(runtime_string_list_t *list) {
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

static int runtime_string_list_reserve(runtime_string_list_t *list, size_t need) {
    char **new_items = NULL;
    size_t new_cap = 0;
    if (need <= list->cap) {
        return 0;
    }
    new_cap = (list->cap == 0) ? 4 : list->cap;
    while (new_cap < need) {
        new_cap *= 2;
    }
    new_items = (char **)realloc(list->items, new_cap * sizeof(*new_items));
    if (new_items == NULL) {
        return -1;
    }
    list->items = new_items;
    list->cap = new_cap;
    return 0;
}

static ssize_t runtime_string_list_find(const runtime_string_list_t *list, const char *value) {
    size_t i = 0;
    if (list == NULL || value == NULL) {
        return -1;
    }
    for (i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static int runtime_string_list_add(runtime_string_list_t *list, const char *value) {
    char *copy = NULL;
    if (list == NULL || value == NULL || value[0] == '\0') {
        return -1;
    }
    if (runtime_string_list_find(list, value) >= 0) {
        return 0;
    }
    if (runtime_string_list_reserve(list, list->count + 1) != 0) {
        return -1;
    }
    copy = (char *)calloc(strlen(value) + 1, 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, value, strlen(value));
    list->items[list->count++] = copy;
    return 0;
}

static int runtime_string_list_remove(runtime_string_list_t *list, const char *value) {
    ssize_t idx = runtime_string_list_find(list, value);
    if (idx < 0) {
        return -1;
    }
    free(list->items[idx]);
    if ((size_t)idx + 1 < list->count) {
        memmove(&list->items[idx], &list->items[idx + 1],
                (list->count - ((size_t)idx + 1)) * sizeof(*list->items));
    }
    list->count--;
    return 0;
}

static int runtime_string_list_copy_from_raw(runtime_string_list_t *list,
                                             const char *const *items, size_t count) {
    size_t i = 0;
    runtime_string_list_free(list);
    for (i = 0; i < count; i++) {
        if (runtime_string_list_add(list, items[i]) != 0) {
            runtime_string_list_free(list);
            return -1;
        }
    }
    return 0;
}

static int runtime_string_list_append_text(const runtime_string_list_t *list, const char *prefix,
                                           char *out, size_t out_sz, size_t *used) {
    size_t i = 0;
    if (appendf_line(out, out_sz, used, "%s_count=%lu\n", prefix,
                     (unsigned long)(list != NULL ? list->count : 0)) != 0) {
        return -1;
    }
    if (list == NULL) {
        return 0;
    }
    for (i = 0; i < list->count; i++) {
        if (appendf_line(out, out_sz, used, "%s[%lu]=%s\n", prefix,
                         (unsigned long)i, list->items[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static void srv_bind_manager_init(srv_bind_manager_t *mgr) {
    memset(mgr, 0, sizeof(*mgr));
    mgr->next_bind_id = 1;
}

static void srv_bind_manager_close_entry(srv_bind_t *b) {
    if (b->present && b->active && b->lfd != OD_SOCK_INVALID) {
        od_socket_close(b->lfd);
    }
    b->active = false;
    b->lfd = OD_SOCK_INVALID;
}

static void srv_bind_manager_destroy(srv_bind_manager_t *mgr) {
    size_t i = 0;
    if (mgr == NULL) {
        return;
    }
    if (mgr->items != NULL) {
        for (i = 0; i < mgr->count; i++) {
            srv_bind_manager_close_entry(&mgr->items[i]);
            mgr->items[i].present = false;
        }
    }
    free(mgr->items);
    memset(mgr, 0, sizeof(*mgr));
}

static int srv_bind_manager_reserve(srv_bind_manager_t *mgr, size_t need) {
    srv_bind_t *new_items = NULL;
    size_t new_cap = 0;
    if (need <= mgr->cap) {
        return 0;
    }
    new_cap = (mgr->cap == 0) ? 8 : mgr->cap;
    while (new_cap < need) {
        new_cap *= 2;
    }
    new_items = (srv_bind_t *)realloc(mgr->items, new_cap * sizeof(*new_items));
    if (new_items == NULL) {
        return -1;
    }
    mgr->items = new_items;
    mgr->cap = new_cap;
    return 0;
}

static int srv_bind_manager_add(srv_bind_manager_t *mgr, const endpoint_t *listen_ep,
                                const endpoint_t *target_ep, socket_t lfd, bool active,
                                uint32_t *out_bind_id) {
    srv_bind_t *b = NULL;
    if (srv_bind_manager_reserve(mgr, mgr->count + 1) != 0) {
        return -1;
    }
    b = &mgr->items[mgr->count++];
    memset(b, 0, sizeof(*b));
    b->present = true;
    b->bind_id = mgr->next_bind_id++;
    if (mgr->next_bind_id == 0) {
        mgr->next_bind_id = 1;
    }
    b->listen_ep = *listen_ep;
    b->target_ep = *target_ep;
    b->lfd = lfd;
    b->active = active;
    if (out_bind_id != NULL) {
        *out_bind_id = b->bind_id;
    }
    return 0;
}

static bool endpoint_equal(const endpoint_t *a, const endpoint_t *b) {
    return a->port == b->port && strcmp(a->host, b->host) == 0;
}

static ssize_t srv_bind_manager_find_active_listen(const srv_bind_manager_t *mgr, const endpoint_t *listen_ep) {
    size_t i = 0;
    for (i = 0; i < mgr->count; i++) {
        if (!mgr->items[i].present || !mgr->items[i].active) {
            continue;
        }
        if (endpoint_equal(&mgr->items[i].listen_ep, listen_ep)) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static ssize_t srv_bind_manager_find_by_id(const srv_bind_manager_t *mgr, uint32_t bind_id) {
    size_t i = 0;
    for (i = 0; i < mgr->count; i++) {
        if (!mgr->items[i].present) {
            continue;
        }
        if (mgr->items[i].bind_id == bind_id) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static uint64_t now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static void sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static int parse_endpoint_text(const char *raw, endpoint_t *out) {
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
    p = strtoul(port_buf, &endptr, 10);
    if (endptr == port_buf || *endptr != '\0' || p == 0UL || p > 65535UL) {
        return -1;
    }
    out->port = (uint16_t)p;
    return 0;
}

static int endpoint_to_text(const endpoint_t *ep, char *out, size_t out_sz) {
    int n = snprintf(out, out_sz, "%s:%u", ep->host, (unsigned)ep->port);
    if (n <= 0 || (size_t)n >= out_sz) {
        return -1;
    }
    return 0;
}

static int parse_bind_rule_text(const char *raw, endpoint_t *listen_ep, endpoint_t *target_ep) {
    char copy[1024];
    char *parts[4];
    int idx = 0;
    char *p = NULL;
    char *endptr = NULL;
    unsigned long lp = 0;
    unsigned long rp = 0;

    memset(copy, 0, sizeof(copy));
    memset(listen_ep, 0, sizeof(*listen_ep));
    memset(target_ep, 0, sizeof(*target_ep));
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
    if (strlen(parts[0]) == 0 || strlen(parts[0]) >= sizeof(listen_ep->host) ||
        strlen(parts[2]) == 0 || strlen(parts[2]) >= sizeof(target_ep->host)) {
        return -1;
    }

    lp = strtoul(parts[1], &endptr, 10);
    if (endptr == parts[1] || *endptr != '\0' || lp == 0UL || lp > 65535UL) {
        return -1;
    }
    rp = strtoul(parts[3], &endptr, 10);
    if (endptr == parts[3] || *endptr != '\0' || rp == 0UL || rp > 65535UL) {
        return -1;
    }

    memcpy(listen_ep->host, parts[0], strlen(parts[0]));
    listen_ep->host[strlen(parts[0])] = '\0';
    listen_ep->port = (uint16_t)lp;
    memcpy(target_ep->host, parts[2], strlen(parts[2]));
    target_ep->host[strlen(parts[2])] = '\0';
    target_ep->port = (uint16_t)rp;
    return 0;
}

static int admin_send_all(socket_t fd, const char *buf, size_t len) {
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

static int admin_recv_line(socket_t fd, char *out, size_t out_sz) {
    size_t used = 0;
    while (used + 1 < out_sz) {
        char c = '\0';
        int n = recv(fd, &c, 1, 0);
        if (n > 0) {
            if (c == '\n') {
                break;
            }
            out[used++] = c;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (od_socket_error_is_retryable(od_socket_last_error())) {
            continue;
        }
        return -1;
    }
    out[used] = '\0';
    while (used > 0 && (out[used - 1] == '\r' || out[used - 1] == '\n' || out[used - 1] == ' ')) {
        out[used - 1] = '\0';
        used--;
    }
    return (used > 0) ? 0 : -1;
}

static int parse_u32_text(const char *raw, uint32_t *out) {
    char *endptr = NULL;
    unsigned long v = strtoul(raw, &endptr, 10);
    if (endptr == raw || *endptr != '\0' || v == 0UL || v > 0xFFFFFFFFUL) {
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int srv_bind_manager_add_live(srv_bind_manager_t *mgr, const endpoint_t *listen_ep,
                                     const endpoint_t *target_ep, uint32_t *out_bind_id,
                                     char *err_buf, size_t err_buf_sz) {
    socket_t lfd = OD_SOCK_INVALID;
    if (srv_bind_manager_find_active_listen(mgr, listen_ep) >= 0) {
        snprintf(err_buf, err_buf_sz, "listen exists");
        return -1;
    }
    lfd = od_open_listener(listen_ep);
    if (lfd == OD_SOCK_INVALID) {
        snprintf(err_buf, err_buf_sz, "bind/listen failed");
        return -1;
    }
    if (srv_bind_manager_add(mgr, listen_ep, target_ep, lfd, true, out_bind_id) != 0) {
        od_socket_close(lfd);
        snprintf(err_buf, err_buf_sz, "out of memory");
        return -1;
    }
    return 0;
}

static int srv_bind_manager_del_live(srv_bind_manager_t *mgr, uint32_t bind_id,
                                     char *err_buf, size_t err_buf_sz) {
    ssize_t idx = srv_bind_manager_find_by_id(mgr, bind_id);
    if (idx < 0) {
        snprintf(err_buf, err_buf_sz, "bind not found");
        return -1;
    }
    srv_bind_manager_close_entry(&mgr->items[idx]);
    mgr->items[idx].present = false;
    return 0;
}

static size_t srv_bind_manager_present_count(const srv_bind_manager_t *mgr) {
    size_t i = 0;
    size_t count = 0;
    for (i = 0; i < mgr->count; i++) {
        if (mgr->items[i].present) {
            count++;
        }
    }
    return count;
}

static size_t srv_stream_used_count(const srv_stream_t *streams, size_t max_streams) {
    size_t i = 0;
    size_t count = 0;
    for (i = 0; i < max_streams; i++) {
        if (streams[i].used) {
            count++;
        }
    }
    return count;
}

static size_t srv_stream_confirmed_count(const srv_stream_t *streams, size_t max_streams) {
    size_t i = 0;
    size_t count = 0;
    for (i = 0; i < max_streams; i++) {
        if (streams[i].used && streams[i].open_confirmed) {
            count++;
        }
    }
    return count;
}

static int append_line(char *out, size_t out_sz, size_t *used, const char *line) {
    int n = 0;
    if (*used >= out_sz) {
        return -1;
    }
    n = snprintf(out + *used, out_sz - *used, "%s", line);
    if (n <= 0 || (size_t)n >= (out_sz - *used)) {
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

static int appendf_line(char *out, size_t out_sz, size_t *used, const char *fmt, ...) {
    va_list ap;
    int n = 0;
    if (*used >= out_sz) {
        return -1;
    }
    va_start(ap, fmt);
    n = vsnprintf(out + *used, out_sz - *used, fmt, ap);
    va_end(ap);
    if (n <= 0 || (size_t)n >= (out_sz - *used)) {
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

static int build_ctrl_response(char *out, size_t out_sz, bool ok, const char *code,
                               const char *reason, const char *data) {
    return (od_proto_build_typed_response(out, out_sz, ok, code, reason, "0", now_ms(), data) < 0)
               ? -1
               : 0;
}

static int parse_ipv4_u32_text(const char *raw, uint32_t *out) {
    struct in_addr a;
    if (raw == NULL || out == NULL || raw[0] == '\0') {
        return -1;
    }
    if (inet_pton(AF_INET, raw, &a) != 1) {
        return -1;
    }
    *out = ntohl(a.s_addr);
    return 0;
}

static int parse_cidr4_text(const char *raw, uint32_t *network, uint32_t *mask) {
    const char *slash = NULL;
    char ip_part[64];
    size_t ip_len = 0;
    char *endptr = NULL;
    unsigned long prefix = 0;
    uint32_t ip_u32 = 0;

    if (raw == NULL || network == NULL || mask == NULL || raw[0] == '\0') {
        return -1;
    }
    slash = strchr(raw, '/');
    if (slash == NULL) {
        if (parse_ipv4_u32_text(raw, &ip_u32) != 0) {
            return -1;
        }
        *mask = 0xFFFFFFFFU;
        *network = ip_u32;
        return 0;
    }
    ip_len = (size_t)(slash - raw);
    if (ip_len == 0 || ip_len >= sizeof(ip_part) || *(slash + 1) == '\0') {
        return -1;
    }
    memcpy(ip_part, raw, ip_len);
    ip_part[ip_len] = '\0';
    if (parse_ipv4_u32_text(ip_part, &ip_u32) != 0) {
        return -1;
    }
    prefix = strtoul(slash + 1, &endptr, 10);
    if (endptr == slash + 1 || *endptr != '\0' || prefix > 32UL) {
        return -1;
    }
    if (prefix == 0UL) {
        *mask = 0U;
    } else {
        *mask = 0xFFFFFFFFU << (32U - (uint32_t)prefix);
    }
    *network = ip_u32 & *mask;
    return 0;
}

static bool ipv4_matches_any_spec(uint32_t ip_u32, const char *const *specs, size_t spec_count) {
    size_t i = 0;
    if (specs == NULL || spec_count == 0) {
        return false;
    }
    for (i = 0; i < spec_count; i++) {
        uint32_t net = 0;
        uint32_t mask = 0;
        if (parse_cidr4_text(specs[i], &net, &mask) != 0) {
            continue;
        }
        if ((ip_u32 & mask) == net) {
            return true;
        }
    }
    return false;
}

static int parse_allow_port_spec(const char *raw, uint8_t *proto, uint16_t *port) {
    char copy[64];
    char *sep = NULL;
    char *endptr = NULL;
    unsigned long p = 0;

    if (raw == NULL || proto == NULL || port == NULL || raw[0] == '\0' || strlen(raw) >= sizeof(copy)) {
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", raw);
    sep = strchr(copy, ':');
    if (sep == NULL || sep == copy || *(sep + 1) == '\0') {
        return -1;
    }
    *sep = '\0';
    if (strcmp(copy, "tcp") == 0) {
        *proto = 6U;
    } else if (strcmp(copy, "udp") == 0) {
        *proto = 17U;
    } else {
        return -1;
    }
    p = strtoul(sep + 1, &endptr, 10);
    if (endptr == sep + 1 || *endptr != '\0' || p == 0UL || p > 65535UL) {
        return -1;
    }
    *port = (uint16_t)p;
    return 0;
}

static bool allow_port_matches(uint8_t proto, uint16_t port, const char *const *allow_ports,
                               size_t allow_port_count) {
    size_t i = 0;
    if (allow_ports == NULL || allow_port_count == 0) {
        return false;
    }
    for (i = 0; i < allow_port_count; i++) {
        uint8_t allow_proto = 0;
        uint16_t allow_port = 0;
        if (parse_allow_port_spec(allow_ports[i], &allow_proto, &allow_port) != 0) {
            continue;
        }
        if (allow_proto == proto && allow_port == port) {
            return true;
        }
    }
    return false;
}

static int packet_ipv4_extract(const uint8_t *pkt, size_t pkt_len, uint32_t *dst_ip,
                               uint8_t *proto, uint16_t *dst_port, bool *has_port) {
    size_t ihl = 0;
    size_t l4_off = 0;
    uint8_t p = 0;
    if (dst_ip != NULL) {
        *dst_ip = 0;
    }
    if (proto != NULL) {
        *proto = 0;
    }
    if (dst_port != NULL) {
        *dst_port = 0;
    }
    if (has_port != NULL) {
        *has_port = false;
    }
    if (pkt == NULL || pkt_len < 20 || (pkt[0] >> 4) != 4U) {
        return -1;
    }
    ihl = (size_t)(pkt[0] & 0x0FU) * 4U;
    if (ihl < 20U || ihl > pkt_len) {
        return -1;
    }
    p = pkt[9];
    if (dst_ip != NULL) {
        *dst_ip = ((uint32_t)pkt[16] << 24) | ((uint32_t)pkt[17] << 16) |
                  ((uint32_t)pkt[18] << 8) | (uint32_t)pkt[19];
    }
    if (proto != NULL) {
        *proto = p;
    }
    if (p == 6U || p == 17U) {
        l4_off = ihl;
        if (pkt_len < l4_off + 4U) {
            return -1;
        }
        if (dst_port != NULL) {
            *dst_port = (uint16_t)(((uint16_t)pkt[l4_off + 2] << 8) | pkt[l4_off + 3]);
        }
        if (has_port != NULL) {
            *has_port = true;
        }
    }
    return 0;
}

static bool packet_allowed_by_specs(const uint8_t *pkt, size_t pkt_len,
                                    const char *const *allow_cidrs, size_t allow_cidr_count,
                                    const char *const *allow_ports, size_t allow_port_count) {
    uint32_t dst_ip = 0;
    uint8_t proto = 0;
    uint16_t dst_port = 0;
    bool has_port = false;
    if (packet_ipv4_extract(pkt, pkt_len, &dst_ip, &proto, &dst_port, &has_port) != 0) {
        return false;
    }
    if (!ipv4_matches_any_spec(dst_ip, allow_cidrs, allow_cidr_count)) {
        return false;
    }
    if (!has_port) {
        return false;
    }
    return allow_port_matches(proto, dst_port, allow_ports, allow_port_count);
}

#ifndef _WIN32
static bool packet_return_allowed_by_specs(const uint8_t *pkt, size_t pkt_len,
                                           const char *const *allow_cidrs, size_t allow_cidr_count,
                                           const char *const *allow_ports, size_t allow_port_count) {
    uint32_t src_ip = 0;
    uint8_t proto = 0;
    uint16_t src_port = 0;
    bool has_port = false;
    size_t ihl = 0;
    size_t l4_off = 0;
    if (pkt == NULL || pkt_len < 20 || (pkt[0] >> 4) != 4U) {
        return false;
    }
    ihl = (size_t)(pkt[0] & 0x0FU) * 4U;
    if (ihl < 20U || ihl > pkt_len) {
        return false;
    }
    proto = pkt[9];
    src_ip = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
             ((uint32_t)pkt[14] << 8) | (uint32_t)pkt[15];
    if (!ipv4_matches_any_spec(src_ip, allow_cidrs, allow_cidr_count)) {
        return false;
    }
    if (proto == 6U || proto == 17U) {
        l4_off = ihl;
        if (pkt_len < l4_off + 4U) {
            return false;
        }
        src_port = (uint16_t)(((uint16_t)pkt[l4_off] << 8) | pkt[l4_off + 1]);
        has_port = true;
    }
    if (!has_port) {
        return false;
    }
    return allow_port_matches(proto, src_port, allow_ports, allow_port_count);
}
#endif /* !_WIN32 */

static bool packet_dst_matches_cidrs(const uint8_t *pkt, size_t pkt_len,
                                     const char *const *allow_cidrs, size_t allow_cidr_count) {
    uint32_t dst_ip = 0;
    if (packet_ipv4_extract(pkt, pkt_len, &dst_ip, NULL, NULL, NULL) != 0) {
        return false;
    }
    return ipv4_matches_any_spec(dst_ip, allow_cidrs, allow_cidr_count);
}

static int send_tun_fail(const od_io_t *ctrl_io, const char *code, const char *reason) {
    char response[1024];
    memset(response, 0, sizeof(response));
    if (build_ctrl_response(response, sizeof(response), false,
                            code != NULL ? code : "tun_error",
                            reason != NULL ? reason : "tun error", "") != 0) {
        const char *msg = "tun error";
        return od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
    }
    return od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, response, (uint32_t)strlen(response));
}

static int validate_runtime_cidr(const char *value) {
    if (value == NULL || value[0] == '\0' || strchr(value, '/') == NULL) {
        return -1;
    }
    if (strcmp(value, "0.0.0.0/0") == 0) {
        return -1;
    }
    return od_hardening_validate_source_spec(value);
}

static int validate_runtime_port(const char *value) {
    uint8_t proto = 0;
    uint16_t port = 0;
    return parse_allow_port_spec(value, &proto, &port);
}

static int tun_policy_cache_to_text(const tun_policy_cache_t *policy, char *out, size_t out_sz) {
    size_t used = 0;
    if (appendf_line(out, out_sz, &used, "policy_known=%s\n",
                     (policy != NULL && policy->known) ? "true" : "false") != 0) {
        return -1;
    }
    if (runtime_string_list_append_text(policy != NULL ? &policy->allow_cidrs : NULL,
                                        "allow_cidr", out, out_sz, &used) != 0 ||
        runtime_string_list_append_text(policy != NULL ? &policy->allow_ports : NULL,
                                        "allow_port", out, out_sz, &used) != 0) {
        return -1;
    }
    return 0;
}

static int tun_gateway_route_list_to_text(char *out, size_t out_sz) {
    size_t used = 0;
    return runtime_string_list_append_text(&g_tun_gateway_ctx.route_allow, "route", out, out_sz, &used);
}

static int tun_gateway_snapshot_to_text(char *out, size_t out_sz) {
    size_t used = 0;
    if (append_line(out, out_sz, &used, "snapshot=tun-gateway\n") != 0 ||
        appendf_line(out, out_sz, &used, "control_connected=%s\n",
                     g_tun_gateway_ctx.control_connected ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "killswitch_manual=%s\n",
                     g_tun_gateway_ctx.killswitch_manual ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "killswitch_blocking=%s\n",
                     (g_tun_gateway_ctx.killswitch_manual || !g_tun_gateway_ctx.control_connected)
                         ? "true" : "false") != 0) {
        return -1;
    }
    if (runtime_string_list_append_text(&g_tun_gateway_ctx.route_allow, "route", out, out_sz, &used) != 0 ||
        runtime_string_list_append_text(&g_tun_gateway_ctx.policy.allow_cidrs, "allow_cidr",
                                        out, out_sz, &used) != 0 ||
        runtime_string_list_append_text(&g_tun_gateway_ctx.policy.allow_ports, "allow_port",
                                        out, out_sz, &used) != 0 ||
        appendf_line(out, out_sz, &used, "pkts_from_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.pkts_from_tun) != 0 ||
        appendf_line(out, out_sz, &used, "pkts_to_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.pkts_to_tun) != 0 ||
        appendf_line(out, out_sz, &used, "drops_from_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.drops_from_tun) != 0 ||
        appendf_line(out, out_sz, &used, "drops_to_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.drops_to_tun) != 0) {
        return -1;
    }
    return 0;
}

static int tun_gateway_apply_route_op(const char *op, const char *value, char *err, size_t err_sz) {
    if (err != NULL && err_sz > 0) {
        err[0] = '\0';
    }
    if (op == NULL || value == NULL) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "invalid route operation");
        }
        return -1;
    }
    if (validate_runtime_cidr(value) != 0) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "invalid route CIDR");
        }
        return -1;
    }
    if (strcmp(op, "add") == 0) {
        if (runtime_string_list_add(&g_tun_gateway_ctx.route_allow, value) != 0) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "route add failed");
            }
            return -1;
        }
        return 0;
    }
    if (strcmp(op, "del") == 0) {
        if (runtime_string_list_remove(&g_tun_gateway_ctx.route_allow, value) != 0) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "route not found");
            }
            return -1;
        }
        return 0;
    }
    if (err != NULL && err_sz > 0) {
        snprintf(err, err_sz, "invalid route operation");
    }
    return -1;
}

static int tun_gateway_apply_policy_delta(const char *op, const char *value, char *err, size_t err_sz) {
    runtime_string_list_t *target = NULL;
    int add_mode = 0;
    if (err != NULL && err_sz > 0) {
        err[0] = '\0';
    }
    if (op == NULL || value == NULL) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "invalid policy operation");
        }
        return -1;
    }
    if (strcmp(op, "allow-cidr-add") == 0 || strcmp(op, "allow-cidr-del") == 0) {
        if (validate_runtime_cidr(value) != 0) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "invalid allow-cidr");
            }
            return -1;
        }
        target = &g_tun_gateway_ctx.policy.allow_cidrs;
        add_mode = (strcmp(op, "allow-cidr-add") == 0);
    } else if (strcmp(op, "allow-port-add") == 0 || strcmp(op, "allow-port-del") == 0) {
        if (validate_runtime_port(value) != 0) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "invalid allow-port");
            }
            return -1;
        }
        target = &g_tun_gateway_ctx.policy.allow_ports;
        add_mode = (strcmp(op, "allow-port-add") == 0);
    } else {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "invalid policy operation");
        }
        return -1;
    }
    g_tun_gateway_ctx.policy.known = true;
    g_tun_gateway_ctx.policy_dirty = true;
    if (add_mode) {
        if (runtime_string_list_add(target, value) != 0) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "policy add failed");
            }
            return -1;
        }
        return 0;
    }
    if (runtime_string_list_remove(target, value) != 0) {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "policy entry not found");
        }
        return -1;
    }
    return 0;
}

static bool packet_allowed_by_runtime_policy(const uint8_t *pkt, size_t pkt_len) {
    if (!g_tun_gateway_ctx.policy.known) {
        return true;
    }
    return packet_allowed_by_specs(pkt, pkt_len,
                                   (const char *const *)g_tun_gateway_ctx.policy.allow_cidrs.items,
                                   g_tun_gateway_ctx.policy.allow_cidrs.count,
                                   (const char *const *)g_tun_gateway_ctx.policy.allow_ports.items,
                                   g_tun_gateway_ctx.policy.allow_ports.count);
}

static int tun_sync_policy_reset(const od_io_t *ctrl_io) {
    const char *reset_cmd = "RESET";
    if (ctrl_io == NULL || !g_tun_gateway_ctx.control_connected) {
        return 0;
    }
    return od_send_frame_io(ctrl_io, OD_MSG_TUN_POLICY_SET, 0, 0,
                            reset_cmd, (uint32_t)strlen(reset_cmd));
}

static int tun_sync_policy_delta(const od_io_t *ctrl_io, const char *op, const char *value) {
    char payload[256];
    if (ctrl_io == NULL || !g_tun_gateway_ctx.control_connected || op == NULL) {
        return 0;
    }
    memset(payload, 0, sizeof(payload));
    if (value != NULL && value[0] != '\0') {
        (void)snprintf(payload, sizeof(payload), "%s\t%s", op, value);
    } else {
        (void)snprintf(payload, sizeof(payload), "%s", op);
    }
    return od_send_frame_io(ctrl_io, OD_MSG_TUN_POLICY_SET, 0, 0, payload, (uint32_t)strlen(payload));
}

static int tun_sync_policy_full(const od_io_t *ctrl_io) {
    size_t i = 0;
    if (!g_tun_gateway_ctx.policy.known) {
        return 0;
    }
    if (tun_sync_policy_reset(ctrl_io) != 0) {
        return -1;
    }
    for (i = 0; i < g_tun_gateway_ctx.policy.allow_cidrs.count; i++) {
        if (tun_sync_policy_delta(ctrl_io, "ALLOW_CIDR_ADD",
                                  g_tun_gateway_ctx.policy.allow_cidrs.items[i]) != 0) {
            return -1;
        }
    }
    for (i = 0; i < g_tun_gateway_ctx.policy.allow_ports.count; i++) {
        if (tun_sync_policy_delta(ctrl_io, "ALLOW_PORT_ADD",
                                  g_tun_gateway_ctx.policy.allow_ports.items[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int tun_sync_killswitch(const od_io_t *ctrl_io) {
    const char *state = g_tun_gateway_ctx.killswitch_manual ? "enabled" : "disabled";
    if (ctrl_io == NULL || !g_tun_gateway_ctx.control_connected) {
        return 0;
    }
    return od_send_frame_io(ctrl_io, OD_MSG_TUN_KILLSWITCH_SET, 0, 0,
                            state, (uint32_t)strlen(state));
}

static void tun_gateway_reset_policy_cache(void) {
    runtime_string_list_free(&g_tun_gateway_ctx.policy.allow_cidrs);
    runtime_string_list_free(&g_tun_gateway_ctx.policy.allow_ports);
    g_tun_gateway_ctx.policy.known = false;
    g_tun_gateway_ctx.policy_dirty = false;
}

static void tun_gateway_parse_policy_response(const char *text) {
    char copy[4096];
    char *line = NULL;
    char *ctx = NULL;
    if (text == NULL || text[0] == '\0' || strlen(text) >= sizeof(copy)) {
        return;
    }
    snprintf(copy, sizeof(copy), "%s", text);
    tun_gateway_reset_policy_cache();
    line = strtok_r(copy, "\n", &ctx);
    while (line != NULL) {
        if (strncmp(line, "policy_known=", 13) == 0) {
            g_tun_gateway_ctx.policy.known = (strcmp(line + 13, "true") == 0);
        } else if (strncmp(line, "allow_cidr[", 11) == 0) {
            char *eq = strchr(line, '=');
            if (eq != NULL) {
                (void)runtime_string_list_add(&g_tun_gateway_ctx.policy.allow_cidrs, eq + 1);
            }
        } else if (strncmp(line, "allow_port[", 11) == 0) {
            char *eq = strchr(line, '=');
            if (eq != NULL) {
                (void)runtime_string_list_add(&g_tun_gateway_ctx.policy.allow_ports, eq + 1);
            }
        }
        line = strtok_r(NULL, "\n", &ctx);
    }
    if (g_tun_gateway_ctx.policy.allow_cidrs.count > 0 || g_tun_gateway_ctx.policy.allow_ports.count > 0) {
        g_tun_gateway_ctx.policy.known = true;
    }
}

static bool is_tun_control_type(uint8_t type) {
    switch (type) {
        case OD_MSG_TUN_CAPS_REQ:
        case OD_MSG_TUN_STATUS_REQ:
        case OD_MSG_TUN_ROUTE_ADD:
        case OD_MSG_TUN_ROUTE_DEL:
        case OD_MSG_TUN_ROUTE_LIST:
        case OD_MSG_TUN_POLICY_SET:
        case OD_MSG_TUN_POLICY_GET:
        case OD_MSG_TUN_SESSION_LIST:
        case OD_MSG_TUN_SESSION_CLOSE:
        case OD_MSG_TUN_KILLSWITCH_SET:
        case OD_MSG_TUN_MTU_SET:
        case OD_MSG_TUN_PKT:
            return true;
        default:
            return false;
    }
}

static uint8_t fail_msg_for_control_type(uint8_t type) {
    if (type == OD_MSG_ADD_BIND || type == OD_MSG_DEL_BIND || type == OD_MSG_LIST_BIND) {
        return OD_MSG_BIND_FAIL;
    }
    if (is_tun_control_type(type)) {
        return OD_MSG_TUN_FAIL;
    }
    return OD_MSG_STREAM_FAIL;
}

static int tun_capabilities_to_text(char *out, size_t out_sz) {
    size_t used = 0;
    const char *runtime = g_tun_gateway_ctx.active ? "dataplane_mvp" : "control_only";
    if (appendf_line(out, out_sz, &used, "proto_version=%u\n", (unsigned)ODY_VERSION) != 0 ||
        append_line(out, out_sz, &used, "tun_scaffold=true\n") != 0 ||
        appendf_line(out, out_sz, &used, "tun_runtime=%s\n", runtime) != 0 ||
        append_line(out, out_sz, &used,
                    "tun_actions=tun_caps_req,tun_status_req,tun_route_add,tun_route_del,tun_route_list,tun_policy_set,tun_policy_get,tun_killswitch_set,tun_pkt,snapshot\n") != 0) {
        return -1;
    }
    return 0;
}

static int tun_status_to_text(char *out, size_t out_sz) {
    size_t used = 0;
    const char *mode = g_tun_gateway_ctx.active ? "dataplane_mvp" : "scaffold";
    if (append_line(out, out_sz, &used, "tun_mode=scaffold\n") != 0 ||
        appendf_line(out, out_sz, &used, "tun_runtime=%s\n", mode) != 0 ||
        append_line(out, out_sz, &used, "tun_default_deny=true\n") != 0 ||
        append_line(out, out_sz, &used, "tun_sessions=0\n") != 0 ||
        appendf_line(out, out_sz, &used, "control_connected=%s\n",
                     g_tun_gateway_ctx.control_connected ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "killswitch_manual=%s\n",
                     g_tun_gateway_ctx.killswitch_manual ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "killswitch_blocking=%s\n",
                     (g_tun_gateway_ctx.killswitch_manual || !g_tun_gateway_ctx.control_connected)
                         ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "route_allow_count=%lu\n",
                     (unsigned long)g_tun_gateway_ctx.route_allow.count) != 0 ||
        appendf_line(out, out_sz, &used, "policy_known=%s\n",
                     g_tun_gateway_ctx.policy.known ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "allow_cidr_count=%lu\n",
                     (unsigned long)g_tun_gateway_ctx.policy.allow_cidrs.count) != 0 ||
        appendf_line(out, out_sz, &used, "allow_port_count=%lu\n",
                     (unsigned long)g_tun_gateway_ctx.policy.allow_ports.count) != 0 ||
        appendf_line(out, out_sz, &used, "pkts_from_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.pkts_from_tun) != 0 ||
        appendf_line(out, out_sz, &used, "pkts_to_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.pkts_to_tun) != 0 ||
        appendf_line(out, out_sz, &used, "bytes_from_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.bytes_from_tun) != 0 ||
        appendf_line(out, out_sz, &used, "bytes_to_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.bytes_to_tun) != 0 ||
        appendf_line(out, out_sz, &used, "drops_from_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.drops_from_tun) != 0 ||
        appendf_line(out, out_sz, &used, "drops_to_tun=%llu\n",
                     (unsigned long long)g_tun_gateway_ctx.drops_to_tun) != 0) {
        return -1;
    }
    return 0;
}

static int bind_capabilities_to_text(char *out, size_t out_sz,
                                     const od_control_admin_policy_t *control_admin_policy,
                                     bool socks_active) {
    size_t used = 0;
    const char *admin_actions =
        g_tun_gateway_ctx.active
            ? "admin_actions=list-bind,add-bind,del-bind,capabilities,status,list-stream,close-stream,route-list,route-add,route-del,policy-show,policy-allow-cidr-add,policy-allow-cidr-del,policy-allow-port-add,policy-allow-port-del,killswitch,snapshot\n"
            : "admin_actions=list-bind,add-bind,del-bind,capabilities,status,list-stream,close-stream\n";
    if (appendf_line(out, out_sz, &used, "proto_version=%u\n", (unsigned)ODY_VERSION) != 0 ||
        append_line(out, out_sz, &used, admin_actions) != 0 ||
        appendf_line(out, out_sz, &used, "control_admin_enabled=%s\n",
                     (control_admin_policy != NULL && control_admin_policy->enabled) ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "control_admin_token_required=%s\n",
                     (control_admin_policy != NULL && control_admin_policy->require_token) ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "control_admin_rate_limit_per_min=%d\n",
                     control_admin_policy != NULL ? control_admin_policy->rate_limit_per_min : 0) != 0 ||
        appendf_line(out, out_sz, &used, "control_admin_max_binds=%lu\n",
                     (unsigned long)(control_admin_policy != NULL ? control_admin_policy->max_binds : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "socks_listener=%s\n", socks_active ? "enabled" : "disabled") != 0) {
        return -1;
    }
    return 0;
}

static int bind_status_to_text(char *out, size_t out_sz, const srv_bind_manager_t *bind_mgr,
                               const srv_stream_t *streams, size_t max_streams,
                               bool socks_active, bool admin_active, const hb_state_t *hb,
                               uint64_t session_started_ms) {
    uint64_t now = now_ms();
    size_t used = 0;
    size_t binds_present = srv_bind_manager_present_count(bind_mgr);
    size_t streams_used = srv_stream_used_count(streams, max_streams);
    size_t streams_confirmed = srv_stream_confirmed_count(streams, max_streams);
    if (appendf_line(out, out_sz, &used, "session_uptime_ms=%llu\n",
                     (unsigned long long)(now >= session_started_ms ? (now - session_started_ms) : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "bind_count=%lu\n", (unsigned long)binds_present) != 0 ||
        appendf_line(out, out_sz, &used, "stream_used=%lu\n", (unsigned long)streams_used) != 0 ||
        appendf_line(out, out_sz, &used, "stream_confirmed=%lu\n", (unsigned long)streams_confirmed) != 0 ||
        appendf_line(out, out_sz, &used, "stream_max=%lu\n", (unsigned long)max_streams) != 0 ||
        appendf_line(out, out_sz, &used, "socks_listener=%s\n", socks_active ? "enabled" : "disabled") != 0 ||
        appendf_line(out, out_sz, &used, "admin_listener=%s\n", admin_active ? "enabled" : "disabled") != 0 ||
        appendf_line(out, out_sz, &used, "heartbeat_ms=%d\n", hb->heartbeat_ms) != 0 ||
        appendf_line(out, out_sz, &used, "heartbeat_timeout_ms=%d\n", hb->heartbeat_timeout_ms) != 0) {
        return -1;
    }
    return 0;
}

static int stream_list_to_text(const srv_stream_t *streams, size_t max_streams, char *out, size_t out_sz) {
    size_t i = 0;
    size_t used = 0;
    if (appendf_line(out, out_sz, &used, "stream_count=%lu\n",
                     (unsigned long)srv_stream_used_count(streams, max_streams)) != 0) {
        return -1;
    }
    for (i = 0; i < max_streams; i++) {
        const srv_stream_t *s = &streams[i];
        if (!s->used) {
            continue;
        }
        if (appendf_line(out, out_sz, &used,
                         "stream_id=%lu open=%s socks=%s target=%s:%u bytes_in=%llu bytes_out=%llu\n",
                         (unsigned long)s->stream_id,
                         s->open_confirmed ? "true" : "false",
                         s->is_socks ? "true" : "false",
                         s->target.host, (unsigned)s->target.port,
                         (unsigned long long)s->bytes_from_local,
                         (unsigned long long)s->bytes_to_local) != 0) {
            return -1;
        }
    }
    return 0;
}

static bool control_admin_rate_allow(int limit_per_min, uint64_t *window_start_ms, size_t *count) {
    uint64_t now = 0;
    if (limit_per_min <= 0) {
        return true;
    }
    now = now_ms();
    if (*window_start_ms == 0 || now < *window_start_ms || (now - *window_start_ms) >= 60000ULL) {
        *window_start_ms = now;
        *count = 0;
    }
    if (*count >= (size_t)limit_per_min) {
        return false;
    }
    (*count)++;
    return true;
}

static int handle_admin_client(socket_t afd, srv_bind_manager_t *bind_mgr, srv_stream_t *streams,
                               size_t max_streams, const hb_state_t *hb, bool socks_active,
                               bool admin_active, uint64_t session_started_ms,
                               const od_control_admin_policy_t *control_admin_policy,
                               const char *admin_token, const od_io_t *ctrl_io) {
    char line[1200];
    const char *cmd = NULL;
    char token_buf[512];
    memset(line, 0, sizeof(line));
    memset(token_buf, 0, sizeof(token_buf));

    if (admin_recv_line(afd, line, sizeof(line)) != 0) {
        return -1;
    }

    cmd = line;
    if (admin_token != NULL) {
        char *tab = strchr(line, '\t');
        if (tab == NULL) {
            (void)admin_send_all(afd, "ERR auth format\n", strlen("ERR auth format\n"));
            return -1;
        }
        *tab = '\0';
        if (strlen(line) >= sizeof(token_buf)) {
            (void)admin_send_all(afd, "ERR auth too long\n", strlen("ERR auth too long\n"));
            return -1;
        }
        memcpy(token_buf, line, strlen(line));
        token_buf[strlen(line)] = '\0';
        cmd = tab + 1;
        if (strcmp(token_buf, admin_token) != 0) {
            (void)admin_send_all(afd, "ERR auth invalid\n", strlen("ERR auth invalid\n"));
            return -1;
        }
    }

    if (strcmp(cmd, "LIST_BIND") == 0) {
        char out[2048];
        size_t i = 0;
        int n = snprintf(out, sizeof(out), "OK list\n");
        for (i = 0; i < bind_mgr->count && n > 0 && (size_t)n < sizeof(out); i++) {
            char le[300];
            char te[300];
            int m = 0;
            if (!bind_mgr->items[i].present) {
                continue;
            }
            if (endpoint_to_text(&bind_mgr->items[i].listen_ep, le, sizeof(le)) != 0 ||
                endpoint_to_text(&bind_mgr->items[i].target_ep, te, sizeof(te)) != 0) {
                continue;
            }
            m = snprintf(out + n, sizeof(out) - (size_t)n, "id=%lu listen=%s target=%s active=%d\n",
                         (unsigned long)bind_mgr->items[i].bind_id, le, te,
                         bind_mgr->items[i].active ? 1 : 0);
            if (m <= 0) {
                break;
            }
            n += m;
        }
        if (n > 0 && (size_t)n < sizeof(out)) {
            (void)snprintf(out + n, sizeof(out) - (size_t)n, "END\n");
        }
        (void)admin_send_all(afd, out, strlen(out));
        return 0;
    }

    if (strncmp(cmd, "ADD_BIND ", 9) == 0) {
        endpoint_t listen_ep;
        endpoint_t target_ep;
        uint32_t bind_id = 0;
        char err[160];
        char out[256];
        memset(err, 0, sizeof(err));
        memset(out, 0, sizeof(out));
        if (parse_bind_rule_text(cmd + 9, &listen_ep, &target_ep) != 0) {
            (void)admin_send_all(afd, "ERR invalid bind format\n", strlen("ERR invalid bind format\n"));
            return -1;
        }
        if (srv_bind_manager_add_live(bind_mgr, &listen_ep, &target_ep, &bind_id, err, sizeof(err)) != 0) {
            (void)snprintf(out, sizeof(out), "ERR %s\n", err);
            (void)admin_send_all(afd, out, strlen(out));
            return -1;
        }
        (void)snprintf(out, sizeof(out), "OK bind_id=%lu\n", (unsigned long)bind_id);
        (void)admin_send_all(afd, out, strlen(out));
        od_log_info("admin add-bind id=%lu %s:%u -> %s:%u",
                    (unsigned long)bind_id, listen_ep.host, (unsigned)listen_ep.port,
                    target_ep.host, (unsigned)target_ep.port);
        return 0;
    }

    if (strncmp(cmd, "DEL_BIND ", 9) == 0) {
        uint32_t bind_id = 0;
        char err[160];
        char out[256];
        memset(err, 0, sizeof(err));
        memset(out, 0, sizeof(out));
        if (parse_u32_text(cmd + 9, &bind_id) != 0) {
            (void)admin_send_all(afd, "ERR invalid bind id\n", strlen("ERR invalid bind id\n"));
            return -1;
        }
        if (srv_bind_manager_del_live(bind_mgr, bind_id, err, sizeof(err)) != 0) {
            (void)snprintf(out, sizeof(out), "ERR %s\n", err);
            (void)admin_send_all(afd, out, strlen(out));
            return -1;
        }
        (void)snprintf(out, sizeof(out), "OK bind_id=%lu deleted\n", (unsigned long)bind_id);
        (void)admin_send_all(afd, out, strlen(out));
        od_log_info("admin del-bind id=%lu", (unsigned long)bind_id);
        return 0;
    }

    if (strcmp(cmd, "CAPABILITIES") == 0) {
        char data[2048];
        char resp[3072];
        memset(data, 0, sizeof(data));
        memset(resp, 0, sizeof(resp));
        if (bind_capabilities_to_text(data, sizeof(data), control_admin_policy, socks_active) != 0 ||
            build_ctrl_response(resp, sizeof(resp), true, "OK", "capabilities", data) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, resp, strlen(resp));
        return 0;
    }

    if (strcmp(cmd, "STATUS") == 0) {
        char data[2048];
        char resp[3072];
        memset(data, 0, sizeof(data));
        memset(resp, 0, sizeof(resp));
        if (bind_status_to_text(data, sizeof(data), bind_mgr, streams, max_streams,
                                socks_active, admin_active, hb, session_started_ms) != 0 ||
            build_ctrl_response(resp, sizeof(resp), true, "OK", "status", data) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, resp, strlen(resp));
        return 0;
    }

    if (strcmp(cmd, "LIST_STREAM") == 0) {
        char data[4096];
        char resp[6144];
        memset(data, 0, sizeof(data));
        memset(resp, 0, sizeof(resp));
        if (stream_list_to_text(streams, max_streams, data, sizeof(data)) != 0 ||
            build_ctrl_response(resp, sizeof(resp), true, "OK", "list-stream", data) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, resp, strlen(resp));
        return 0;
    }

    if (strncmp(cmd, "CLOSE_STREAM ", 13) == 0) {
        uint32_t stream_id = 0;
        size_t i = 0;
        if (parse_u32_text(cmd + 13, &stream_id) != 0) {
            (void)admin_send_all(afd, "ERR invalid stream id\n", strlen("ERR invalid stream id\n"));
            return -1;
        }
        for (i = 0; i < max_streams; i++) {
            srv_stream_t *s = &streams[i];
            if (!s->used || s->stream_id != stream_id) {
                continue;
            }
            if (s->local_fd != OD_SOCK_INVALID) {
                od_socket_close(s->local_fd);
            }
            memset(s, 0, sizeof(*s));
            s->local_fd = OD_SOCK_INVALID;
            (void)admin_send_all(afd, "OK stream closed\n", strlen("OK stream closed\n"));
            od_log_info("admin close-stream id=%lu", (unsigned long)stream_id);
            return 0;
        }
        (void)admin_send_all(afd, "ERR stream not found\n", strlen("ERR stream not found\n"));
        return -1;
    }

    if (strcmp(cmd, "ROUTE_LIST") == 0) {
        char data[2048];
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        memset(data, 0, sizeof(data));
        if (tun_gateway_route_list_to_text(data, sizeof(data)) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, data, strlen(data));
        return 0;
    }

    if (strncmp(cmd, "ROUTE_ADD ", 10) == 0 || strncmp(cmd, "ROUTE_DEL ", 10) == 0) {
        const char *op = (strncmp(cmd, "ROUTE_ADD ", 10) == 0) ? "add" : "del";
        const char *value = cmd + 10;
        char err[160];
        char out[256];
        memset(err, 0, sizeof(err));
        memset(out, 0, sizeof(out));
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        if (tun_gateway_apply_route_op(op, value, err, sizeof(err)) != 0) {
            (void)snprintf(out, sizeof(out), "ERR %s\n", err);
            (void)admin_send_all(afd, out, strlen(out));
            return -1;
        }
        (void)snprintf(out, sizeof(out), "OK route %s %s\n",
                       strcmp(op, "add") == 0 ? "added" : "deleted", value);
        (void)admin_send_all(afd, out, strlen(out));
        return 0;
    }

    if (strcmp(cmd, "POLICY_SHOW") == 0) {
        char data[2048];
        char resp[3072];
        memset(data, 0, sizeof(data));
        memset(resp, 0, sizeof(resp));
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        if (tun_policy_cache_to_text(&g_tun_gateway_ctx.policy, data, sizeof(data)) != 0 ||
            build_ctrl_response(resp, sizeof(resp), true, "OK", "policy-show", data) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, resp, strlen(resp));
        return 0;
    }

    if (strncmp(cmd, "POLICY_ALLOW_CIDR_ADD ", 22) == 0 ||
        strncmp(cmd, "POLICY_ALLOW_CIDR_DEL ", 22) == 0 ||
        strncmp(cmd, "POLICY_ALLOW_PORT_ADD ", 22) == 0 ||
        strncmp(cmd, "POLICY_ALLOW_PORT_DEL ", 22) == 0) {
        char op[64];
        const char *value = cmd + 22;
        char err[160];
        char out[256];
        memset(op, 0, sizeof(op));
        memset(err, 0, sizeof(err));
        memset(out, 0, sizeof(out));
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        if (strncmp(cmd, "POLICY_ALLOW_CIDR_ADD ", 22) == 0) {
            snprintf(op, sizeof(op), "allow-cidr-add");
        } else if (strncmp(cmd, "POLICY_ALLOW_CIDR_DEL ", 22) == 0) {
            snprintf(op, sizeof(op), "allow-cidr-del");
        } else if (strncmp(cmd, "POLICY_ALLOW_PORT_ADD ", 22) == 0) {
            snprintf(op, sizeof(op), "allow-port-add");
        } else {
            snprintf(op, sizeof(op), "allow-port-del");
        }
        if (tun_gateway_apply_policy_delta(op, value, err, sizeof(err)) != 0) {
            (void)snprintf(out, sizeof(out), "ERR %s\n", err);
            (void)admin_send_all(afd, out, strlen(out));
            return -1;
        }
        (void)tun_sync_policy_delta(ctrl_io,
                                    strcmp(op, "allow-cidr-add") == 0 ? "ALLOW_CIDR_ADD" :
                                    strcmp(op, "allow-cidr-del") == 0 ? "ALLOW_CIDR_DEL" :
                                    strcmp(op, "allow-port-add") == 0 ? "ALLOW_PORT_ADD" :
                                    "ALLOW_PORT_DEL",
                                    value);
        (void)snprintf(out, sizeof(out), "OK policy %s %s\n", op, value);
        (void)admin_send_all(afd, out, strlen(out));
        return 0;
    }

    if (strncmp(cmd, "KILLSWITCH ", 11) == 0) {
        const char *state = cmd + 11;
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        if (strcmp(state, "on") == 0 || strcmp(state, "enabled") == 0) {
            g_tun_gateway_ctx.killswitch_manual = true;
        } else if (strcmp(state, "off") == 0 || strcmp(state, "disabled") == 0) {
            g_tun_gateway_ctx.killswitch_manual = false;
        } else {
            (void)admin_send_all(afd, "ERR expected on|off\n", strlen("ERR expected on|off\n"));
            return -1;
        }
        (void)tun_sync_killswitch(ctrl_io);
        (void)admin_send_all(afd, "OK killswitch updated\n", strlen("OK killswitch updated\n"));
        return 0;
    }

    if (strcmp(cmd, "SNAPSHOT") == 0) {
        char data[4096];
        char resp[6144];
        memset(data, 0, sizeof(data));
        memset(resp, 0, sizeof(resp));
        if (!g_tun_gateway_ctx.active) {
            (void)admin_send_all(afd, "ERR tun runtime not active\n", strlen("ERR tun runtime not active\n"));
            return -1;
        }
        if (tun_gateway_snapshot_to_text(data, sizeof(data)) != 0 ||
            build_ctrl_response(resp, sizeof(resp), true, "OK", "snapshot", data) != 0) {
            (void)admin_send_all(afd, "ERR internal error\n", strlen("ERR internal error\n"));
            return -1;
        }
        (void)admin_send_all(afd, resp, strlen(resp));
        return 0;
    }

    (void)admin_send_all(afd, "ERR unknown command\n", strlen("ERR unknown command\n"));
    return -1;
}

static void bind_list_to_text(const srv_bind_manager_t *bind_mgr, char *out, size_t out_sz) {
    size_t i = 0;
    int n = 0;
    if (out_sz == 0) {
        return;
    }
    out[0] = '\0';
    n = snprintf(out, out_sz, "list\n");
    for (i = 0; i < bind_mgr->count && n > 0 && (size_t)n < out_sz; i++) {
        char le[300];
        char te[300];
        int m = 0;
        if (!bind_mgr->items[i].present) {
            continue;
        }
        if (endpoint_to_text(&bind_mgr->items[i].listen_ep, le, sizeof(le)) != 0 ||
            endpoint_to_text(&bind_mgr->items[i].target_ep, te, sizeof(te)) != 0) {
            continue;
        }
        m = snprintf(out + n, out_sz - (size_t)n, "id=%lu listen=%s target=%s active=%d\n",
                     (unsigned long)bind_mgr->items[i].bind_id, le, te,
                     bind_mgr->items[i].active ? 1 : 0);
        if (m <= 0) {
            break;
        }
        n += m;
    }
}

static void frame_payload_to_text(const od_frame_t *frame, char *out, size_t out_sz) {
    size_t copy_len = 0;
    size_t i = 0;
    if (out == NULL || out_sz == 0) {
        return;
    }
    if (frame == NULL || frame->payload == NULL || frame->hdr.length == 0) {
        snprintf(out, out_sz, "no-reason");
        return;
    }
    copy_len = (frame->hdr.length < (uint32_t)(out_sz - 1)) ? (size_t)frame->hdr.length : (out_sz - 1);
    memcpy(out, frame->payload, copy_len);
    out[copy_len] = '\0';

    for (i = 0; i < copy_len; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c < 32 || c > 126) {
            out[i] = '?';
        }
    }
}

static uint8_t map_open_fail_reason_to_socks_rep(const char *reason) {
    if (reason == NULL || reason[0] == '\0') {
        return OD_SOCKS_REP_GENERAL_FAILURE;
    }
    if (strstr(reason, "target not allowed") != NULL) {
        return OD_SOCKS_REP_RULESET_DENIED;
    }
    if (strstr(reason, "capacity reached") != NULL) {
        return OD_SOCKS_REP_GENERAL_FAILURE;
    }
    if (strstr(reason, "dns_error:") != NULL || strstr(reason, "Name or service not known") != NULL) {
        return OD_SOCKS_REP_HOST_UNREACHABLE;
    }
    if (strstr(reason, "timed out") != NULL || strstr(reason, "timeout") != NULL) {
        return OD_SOCKS_REP_HOST_UNREACHABLE;
    }
    if (strstr(reason, "refused") != NULL) {
        return OD_SOCKS_REP_CONNECTION_REFUSED;
    }
    return OD_SOCKS_REP_GENERAL_FAILURE;
}

static knock_listener_t *open_knock_listeners(const char *host, od_hardening_state_t *hard_state,
                                              size_t *out_count) {
    knock_listener_t *listeners = NULL;
    size_t count = 0;
    size_t i = 0;

    if (out_count != NULL) {
        *out_count = 0;
    }
    if (hard_state == NULL || !od_hardening_has_knock(hard_state)) {
        return NULL;
    }

    count = od_hardening_knock_count(hard_state);
    listeners = (knock_listener_t *)calloc(count, sizeof(*listeners));
    if (listeners == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        snprintf(ep.host, sizeof(ep.host), "%s", host);
        ep.port = od_hardening_knock_port_at(hard_state, i);
        listeners[i].port = ep.port;
        listeners[i].lfd = od_open_listener(&ep);
        listeners[i].active = (listeners[i].lfd != OD_SOCK_INVALID);
        if (!listeners[i].active) {
            od_log_warn("failed knock listener %s:%u", ep.host, (unsigned)ep.port);
        } else {
            od_log_info("knock listener on %s:%u", ep.host, (unsigned)ep.port);
        }
    }

    if (out_count != NULL) {
        *out_count = count;
    }
    return listeners;
}

static void seed_prng_once(void) {
    static bool seeded = false;
    if (seeded) {
        return;
    }
#ifdef _WIN32
    srand((unsigned int)(GetTickCount64() ^ GetCurrentProcessId()));
#else
    srand((unsigned int)(now_ms() ^ (uint64_t)getpid()));
#endif
    seeded = true;
}

static int backoff_with_jitter_ms(int base_ms) {
    int range = 0;
    int delta = 0;
    if (base_ms <= 0) {
        return 1000;
    }
    range = base_ms / 5;
    if (range <= 0) {
        return base_ms;
    }
    delta = (rand() % (range * 2 + 1)) - range;
    if (base_ms + delta <= 0) {
        return 1000;
    }
    return base_ms + delta;
}

static int recv_expected(const od_io_t *ctrl_io, uint8_t expected_type, od_frame_t *out, bool *closed) {
    if (od_recv_frame_io(ctrl_io, out, closed) != 0) {
        return -1;
    }
    if (*closed) {
        od_log_warn("control channel closed");
        return -1;
    }
    if (out->hdr.type != expected_type) {
        od_log_warn("unexpected control message: got=%s expected=%s",
                    od_msg_type_name(out->hdr.type), od_msg_type_name(expected_type));
        od_frame_free(out);
        return -1;
    }
    return 0;
}

static int do_server_handshake(const od_io_t *ctrl_io, const char *token) {
    od_frame_t frame;
    bool closed = false;
    bool auth_ok = false;
    size_t token_len = strlen(token);

    memset(&frame, 0, sizeof(frame));
    if (recv_expected(ctrl_io, OD_MSG_HELLO, &frame, &closed) != 0) {
        return -1;
    }
    od_frame_free(&frame);

    if (od_send_frame_io(ctrl_io, OD_MSG_HELLO, 0, 0, HELLO_TEXT, (uint32_t)strlen(HELLO_TEXT)) != 0) {
        return -1;
    }

    memset(&frame, 0, sizeof(frame));
    if (recv_expected(ctrl_io, OD_MSG_AUTH, &frame, &closed) != 0) {
        return -1;
    }

    auth_ok = (frame.hdr.length == token_len && memcmp(frame.payload, token, token_len) == 0);
    od_frame_free(&frame);
    if (!auth_ok) {
        const char *msg = "invalid token";
        (void)od_send_frame_io(ctrl_io, OD_MSG_AUTH_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
        od_log_warn("client auth failed");
        return -1;
    }

    if (od_send_frame_io(ctrl_io, OD_MSG_AUTH_OK, 0, 0, NULL, 0) != 0) {
        return -1;
    }
    od_log_info("client authenticated");
    return 0;
}

static int do_client_handshake(const od_io_t *ctrl_io, const char *token) {
    od_frame_t frame;
    bool closed = false;
    size_t token_len = strlen(token);

    memset(&frame, 0, sizeof(frame));
    if (od_send_frame_io(ctrl_io, OD_MSG_HELLO, 0, 0, HELLO_TEXT, (uint32_t)strlen(HELLO_TEXT)) != 0) {
        return -1;
    }

    if (recv_expected(ctrl_io, OD_MSG_HELLO, &frame, &closed) != 0) {
        return -1;
    }
    od_frame_free(&frame);

    if (od_send_frame_io(ctrl_io, OD_MSG_AUTH, 0, 0, token, (uint32_t)token_len) != 0) {
        return -1;
    }

    if (od_recv_frame_io(ctrl_io, &frame, &closed) != 0) {
        return -1;
    }
    if (closed) {
        od_log_warn("control channel closed during auth");
        return -1;
    }
    if (frame.hdr.type == OD_MSG_AUTH_FAIL) {
        od_log_warn("server rejected auth token");
        od_frame_free(&frame);
        return -1;
    }
    if (frame.hdr.type != OD_MSG_AUTH_OK) {
        od_log_warn("unexpected auth response: %s", od_msg_type_name(frame.hdr.type));
        od_frame_free(&frame);
        return -1;
    }

    od_frame_free(&frame);
    od_log_info("authenticated to server");
    return 0;
}

static void hb_init(hb_state_t *hb, int heartbeat_ms, int heartbeat_timeout_ms, bool verbose) {
    hb->heartbeat_ms = heartbeat_ms;
    hb->heartbeat_timeout_ms = heartbeat_timeout_ms;
    hb->verbose = verbose;
    hb->last_ping_ms = now_ms();
    hb->last_rx_ms = now_ms();
}

static int hb_on_frame(const od_io_t *ctrl_io, hb_state_t *hb, const od_frame_t *frame) {
    hb->last_rx_ms = now_ms();

    if (frame->hdr.type == OD_MSG_PING) {
        if (od_send_frame_io(ctrl_io, OD_MSG_PONG, 0, 0, NULL, 0) != 0) {
            return -1;
        }
    } else if (frame->hdr.type == OD_MSG_PONG) {
        if (hb->verbose) {
            od_log_info("PONG received");
        }
    }

    return 0;
}

static int hb_tick(const od_io_t *ctrl_io, hb_state_t *hb) {
    uint64_t now = now_ms();

    if ((int)(now - hb->last_ping_ms) >= hb->heartbeat_ms) {
        if (od_send_frame_io(ctrl_io, OD_MSG_PING, 0, 0, NULL, 0) != 0) {
            return -1;
        }
        hb->last_ping_ms = now;
        if (hb->verbose) {
            od_log_info("PING sent");
        }
    }

    if ((int)(now - hb->last_rx_ms) >= hb->heartbeat_timeout_ms) {
        od_log_warn("heartbeat timeout (%d ms)", hb->heartbeat_timeout_ms);
        return -1;
    }

    return 0;
}

static int socket_write_all(socket_t fd, const uint8_t *buf, uint32_t len) {
    uint32_t off = 0;
    while (off < len) {
        int n = send(fd, (const char *)(buf + off), (int)(len - off), 0);
        if (n > 0) {
            off += (uint32_t)n;
            continue;
        }
        if (n == 0) {
            return -1;
        }
        if (od_socket_error_is_retryable(od_socket_last_error())) {
            continue;
        }
        od_socket_log_error("send(socket_write_all)");
        return -1;
    }
    return 0;
}

static ssize_t find_free_srv_stream(srv_stream_t *streams, size_t max_streams) {
    size_t i = 0;
    for (i = 0; i < max_streams; i++) {
        if (!streams[i].used) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static ssize_t find_srv_stream_by_id(srv_stream_t *streams, size_t max_streams, uint32_t stream_id) {
    size_t i = 0;
    for (i = 0; i < max_streams; i++) {
        if (streams[i].used && streams[i].stream_id == stream_id) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void close_srv_stream(srv_stream_t *s) {
    if (!s->used) {
        return;
    }
    if (s->local_fd != OD_SOCK_INVALID) {
        od_socket_close(s->local_fd);
    }
    od_log_stream("info", s->stream_id,
                  "closed bytes_local_to_target=%lu bytes_target_to_local=%lu",
                  (unsigned long)s->bytes_from_local, (unsigned long)s->bytes_to_local);
    memset(s, 0, sizeof(*s));
    s->local_fd = OD_SOCK_INVALID;
}

static ssize_t find_free_cli_stream(cli_stream_t *streams, size_t max_streams) {
    size_t i = 0;
    for (i = 0; i < max_streams; i++) {
        if (!streams[i].used) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static ssize_t find_cli_stream_by_id(cli_stream_t *streams, size_t max_streams, uint32_t stream_id) {
    size_t i = 0;
    for (i = 0; i < max_streams; i++) {
        if (streams[i].used && streams[i].stream_id == stream_id) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void close_cli_stream(cli_stream_t *s) {
    if (!s->used) {
        return;
    }
    if (s->target_fd != OD_SOCK_INVALID) {
        od_socket_close(s->target_fd);
    }
    od_log_stream("info", s->stream_id,
                  "closed bytes_target_to_server=%lu bytes_server_to_target=%lu",
                  (unsigned long)s->bytes_from_target, (unsigned long)s->bytes_to_target);
    memset(s, 0, sizeof(*s));
    s->target_fd = OD_SOCK_INVALID;
}

static bool is_target_allowed(const endpoint_t *target, const endpoint_t *allow_targets,
                              size_t allow_count) {
    size_t i = 0;
    if (allow_count == 0) {
        return true;
    }
    for (i = 0; i < allow_count; i++) {
        if (allow_targets[i].port == target->port &&
            strcmp(allow_targets[i].host, target->host) == 0) {
            return true;
        }
    }
    return false;
}

static int run_server_control_only_loop(socket_t cfd, const od_io_t *ctrl_io, hb_state_t *hb,
                                        od_hardening_state_t *hard_state,
                                        const knock_listener_t *knock_listeners, size_t knock_count) {
    for (;;) {
        pollfd_t *fds = NULL;
        size_t *knock_map = NULL;
        size_t nfds = 0;
        size_t i = 0;
        int rc = 0;

        fds = (pollfd_t *)calloc(1 + knock_count, sizeof(*fds));
        knock_map = (size_t *)calloc(1 + knock_count, sizeof(*knock_map));
        if (fds == NULL || knock_map == NULL) {
            free(fds);
            free(knock_map);
            od_log_error("out of memory");
            return -1;
        }

        fds[nfds].fd = cfd;
        fds[nfds].events = OD_SOCK_POLLIN;
        nfds++;

        for (i = 0; i < knock_count; i++) {
            if (!knock_listeners[i].active) {
                continue;
            }
            fds[nfds].fd = knock_listeners[i].lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            knock_map[nfds] = i;
            nfds++;
        }

        rc = od_socket_poll(fds, (unsigned long)nfds, DEFAULT_POLL_MS);
        if (rc < 0) {
            free(fds);
            free(knock_map);
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(control)");
            return -1;
        }

        if (rc > 0) {
            for (i = 1; i < nfds; i++) {
                if (!(fds[i].revents & OD_SOCK_POLLIN)) {
                    continue;
                }
                if (hard_state != NULL) {
                    char peer_host[NI_MAXHOST];
                    uint16_t peer_port = 0;
                    socket_t kfd = od_accept_with_peer(fds[i].fd, peer_host, sizeof(peer_host), &peer_port);
                    if (kfd != OD_SOCK_INVALID) {
                        od_hardening_on_knock(hard_state, peer_host, knock_listeners[knock_map[i]].port);
                        od_socket_close(kfd);
                    }
                }
            }
        }

        if (rc > 0 && (fds[0].revents & OD_SOCK_POLLIN)) {
            od_frame_t frame;
            bool closed = false;
            memset(&frame, 0, sizeof(frame));
            if (od_recv_frame_io(ctrl_io, &frame, &closed) != 0) {
                free(fds);
                free(knock_map);
                return -1;
            }
            if (closed) {
                od_log_warn("control channel closed by peer");
                free(fds);
                free(knock_map);
                return -1;
            }
            if (hb_on_frame(ctrl_io, hb, &frame) != 0) {
                od_frame_free(&frame);
                free(fds);
                free(knock_map);
                return -1;
            }
            od_frame_free(&frame);
        }

        free(fds);
        free(knock_map);

        if (hb_tick(ctrl_io, hb) != 0) {
            return -1;
        }
    }
}

static int run_server_multiplex_loop(socket_t cfd, const od_io_t *ctrl_io,
                                     const od_bind_rule_t *bind_rules, size_t bind_count,
                                     const od_socks_server_opts_t *socks_opts,
                                     size_t max_streams, hb_state_t *hb,
                                     od_hardening_state_t *hard_state,
                                     const knock_listener_t *knock_listeners, size_t knock_count,
                                     const endpoint_t *admin_listen_ep, const char *admin_token,
                                     const od_control_admin_policy_t *control_admin_policy) {
    srv_bind_manager_t bind_mgr;
    srv_stream_t *streams = NULL;
    socket_t socks_lfd = OD_SOCK_INVALID;
    socket_t admin_lfd = OD_SOCK_INVALID;
    bool socks_active = false;
    bool admin_active = false;
    bool tun_active = (g_tun_gateway_ctx.active && g_tun_gateway_ctx.tun_fd >= 0);
    od_tun_dev_t tun_dev;
    uint32_t next_stream_id = 1;
    uint64_t session_started_ms = now_ms();
    uint64_t control_admin_rate_window_ms = 0;
    size_t control_admin_rate_count = 0;
    size_t i = 0;
    int ret = -1;

    srv_bind_manager_init(&bind_mgr);
    memset(&tun_dev, 0, sizeof(tun_dev));
    tun_dev.fd = tun_active ? g_tun_gateway_ctx.tun_fd : -1;
    tun_dev.active = tun_active;
    streams = (srv_stream_t *)calloc(max_streams, sizeof(*streams));
    if (streams == NULL) {
        od_log_error("out of memory");
        goto cleanup;
    }

    for (i = 0; i < max_streams; i++) {
        streams[i].local_fd = OD_SOCK_INVALID;
    }

    for (i = 0; i < bind_count; i++) {
        socket_t lfd = od_open_listener(&bind_rules[i].listen_ep);
        bool active = (lfd != OD_SOCK_INVALID);
        uint32_t bind_id = 0;
        if (srv_bind_manager_add(&bind_mgr, &bind_rules[i].listen_ep, &bind_rules[i].target_ep,
                                 lfd, active, &bind_id) != 0) {
            if (active) {
                od_socket_close(lfd);
            }
            od_log_error("out of memory");
            goto cleanup;
        }
        if (!active) {
            od_log_warn("failed bind listener %s:%u", bind_rules[i].listen_ep.host,
                        (unsigned)bind_rules[i].listen_ep.port);
            continue;
        }
        od_log_info("reverse bind id=%lu listening on %s:%u -> %s:%u",
                    (unsigned long)bind_id,
                    bind_rules[i].listen_ep.host, (unsigned)bind_rules[i].listen_ep.port,
                    bind_rules[i].target_ep.host, (unsigned)bind_rules[i].target_ep.port);
    }

    if (socks_opts != NULL && socks_opts->listen_ep != NULL) {
        socks_lfd = od_open_listener(socks_opts->listen_ep);
        if (socks_lfd == OD_SOCK_INVALID) {
            od_log_warn("failed socks listener %s:%u",
                        socks_opts->listen_ep->host, (unsigned)socks_opts->listen_ep->port);
        } else {
            socks_active = true;
            od_log_info("socks5 listening on %s:%u auth=%s",
                        socks_opts->listen_ep->host, (unsigned)socks_opts->listen_ep->port,
                        (socks_opts->username != NULL && socks_opts->password != NULL) ? "userpass" : "none");
        }
    }
    if (admin_listen_ep != NULL) {
        admin_lfd = od_open_listener(admin_listen_ep);
        if (admin_lfd == OD_SOCK_INVALID) {
            od_log_warn("failed admin listener %s:%u", admin_listen_ep->host, (unsigned)admin_listen_ep->port);
        } else {
            admin_active = true;
            od_log_info("admin listening on %s:%u", admin_listen_ep->host, (unsigned)admin_listen_ep->port);
        }
    }
    if (tun_active) {
        g_tun_gateway_ctx.control_connected = true;
        if (g_tun_gateway_ctx.policy.known || g_tun_gateway_ctx.policy_dirty) {
            if (tun_sync_policy_full(ctrl_io) != 0) {
                od_log_warn("failed to sync cached tun policy to agent");
            }
        } else {
            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_POLICY_GET, 0, 0, NULL, 0);
        }
        if (tun_sync_killswitch(ctrl_io) != 0) {
            od_log_warn("failed to sync killswitch state to agent");
        }
    }

    for (;;) {
        pollfd_t *fds = NULL;
        poll_meta_t *meta = NULL;
        size_t nfds = 0;
        size_t cap = 1 + bind_mgr.count + (socks_active ? 1 : 0) + (admin_active ? 1 : 0) +
                     (tun_active ? 1 : 0) +
                     knock_count + max_streams;
        int rc = 0;

        fds = (pollfd_t *)calloc(cap, sizeof(*fds));
        meta = (poll_meta_t *)calloc(cap, sizeof(*meta));
        if (fds == NULL || meta == NULL) {
            free(fds);
            free(meta);
            od_log_error("out of memory");
            break;
        }

        fds[nfds].fd = cfd;
        fds[nfds].events = OD_SOCK_POLLIN;
        meta[nfds].kind = POLL_KIND_CONTROL;
        meta[nfds].idx = 0;
        nfds++;

        for (i = 0; i < bind_mgr.count; i++) {
            if (!bind_mgr.items[i].active) {
                continue;
            }
            fds[nfds].fd = bind_mgr.items[i].lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_LISTENER;
            meta[nfds].idx = i;
            nfds++;
        }

        if (socks_active) {
            fds[nfds].fd = socks_lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_SOCKS_LISTENER;
            meta[nfds].idx = 0;
            nfds++;
        }
        if (admin_active) {
            fds[nfds].fd = admin_lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_ADMIN_LISTENER;
            meta[nfds].idx = 0;
            nfds++;
        }
        if (tun_active) {
            fds[nfds].fd = (socket_t)tun_dev.fd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_TUN_DEV;
            meta[nfds].idx = 0;
            nfds++;
        }

        for (i = 0; i < knock_count; i++) {
            if (!knock_listeners[i].active) {
                continue;
            }
            fds[nfds].fd = knock_listeners[i].lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_KNOCK_LISTENER;
            meta[nfds].idx = i;
            nfds++;
        }

        for (i = 0; i < max_streams; i++) {
            if (!streams[i].used || !streams[i].open_confirmed) {
                continue;
            }
            fds[nfds].fd = streams[i].local_fd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_STREAM;
            meta[nfds].idx = i;
            nfds++;
        }

        rc = od_socket_poll(fds, (unsigned long)nfds, DEFAULT_POLL_MS);
        if (rc < 0) {
            free(fds);
            free(meta);
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(reverse-server)");
            break;
        }

        for (i = 0; i < nfds; i++) {
            if (!(fds[i].revents & (OD_SOCK_POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
                continue;
            }

            if (meta[i].kind == POLL_KIND_CONTROL) {
                od_frame_t frame;
                bool closed = false;
                memset(&frame, 0, sizeof(frame));
                if (od_recv_frame_io(ctrl_io, &frame, &closed) != 0) {
                    free(fds);
                    free(meta);
                    goto cleanup;
                }
                if (closed) {
                    od_log_warn("control channel closed by peer");
                    od_frame_free(&frame);
                    free(fds);
                    free(meta);
                    goto cleanup;
                }

                if (hb_on_frame(ctrl_io, hb, &frame) != 0) {
                    od_frame_free(&frame);
                    free(fds);
                    free(meta);
                    goto cleanup;
                }

                if (frame.hdr.type == OD_MSG_OPEN_OK || frame.hdr.type == OD_MSG_OPEN_FAIL ||
                    frame.hdr.type == OD_MSG_DATA || frame.hdr.type == OD_MSG_CLOSE) {
                    ssize_t sidx = find_srv_stream_by_id(streams, max_streams, frame.hdr.stream_id);
                    if (sidx >= 0) {
                        srv_stream_t *s = &streams[sidx];
                        if (frame.hdr.type == OD_MSG_OPEN_OK) {
                            if (s->is_socks && !s->socks_reply_sent) {
                                if (od_socks_send_reply(s->local_fd, OD_SOCKS_REP_SUCCEEDED) != 0) {
                                    od_log_stream("warn", s->stream_id, "failed to send SOCKS success reply");
                                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                                    close_srv_stream(s);
                                    od_frame_free(&frame);
                                    continue;
                                }
                                s->socks_reply_sent = true;
                            }
                            s->open_confirmed = true;
                            od_log_stream("info", s->stream_id, "open confirmed");
                        } else if (frame.hdr.type == OD_MSG_OPEN_FAIL) {
                            char reason[160];
                            frame_payload_to_text(&frame, reason, sizeof(reason));
                            od_log_stream("warn", s->stream_id, "open failed by client reason=%s", reason);
                            if (s->is_socks && !s->socks_reply_sent) {
                                (void)od_socks_send_reply(s->local_fd, map_open_fail_reason_to_socks_rep(reason));
                                s->socks_reply_sent = true;
                            }
                            close_srv_stream(s);
                        } else if (frame.hdr.type == OD_MSG_DATA && s->open_confirmed) {
                            if (socket_write_all(s->local_fd, frame.payload, frame.hdr.length) != 0) {
                                od_log_stream("warn", s->stream_id, "local write failed");
                                (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                                close_srv_stream(s);
                            } else {
                                s->bytes_to_local += frame.hdr.length;
                            }
                        } else if (frame.hdr.type == OD_MSG_CLOSE) {
                            od_log_stream("info", s->stream_id, "close from client");
                            close_srv_stream(s);
                        }
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_POLICY_RESP && frame.hdr.stream_id == 0) {
                    char policy_text[4096];
                    size_t plen = 0;
                    memset(policy_text, 0, sizeof(policy_text));
                    plen = (frame.hdr.length < sizeof(policy_text) - 1) ? frame.hdr.length : (sizeof(policy_text) - 1);
                    if (frame.payload != NULL && plen > 0) {
                        memcpy(policy_text, frame.payload, plen);
                    }
                    policy_text[plen] = '\0';
                    tun_gateway_parse_policy_response(policy_text);
                } else if ((frame.hdr.type == OD_MSG_TUN_OK || frame.hdr.type == OD_MSG_TUN_FAIL) &&
                           frame.hdr.stream_id == 0) {
                    /* Best-effort sync messages from gateway to tun-agent may respond here. */
                } else if (frame.hdr.type == OD_MSG_TUN_PKT && frame.hdr.stream_id == 0) {
                    if (!tun_active) {
                        (void)send_tun_fail(ctrl_io, "unsupported_capability",
                                            "gateway tun dataplane is not active");
                        od_frame_free(&frame);
                        continue;
                    }
                    if (frame.hdr.length == 0 || frame.hdr.length > OD_TUN_MAX_PACKET) {
                        g_tun_gateway_ctx.drops_to_tun++;
                        (void)send_tun_fail(ctrl_io, "invalid_packet", "invalid tun packet length");
                        od_frame_free(&frame);
                        continue;
                    }
                    if (od_tun_dev_write_packet(&tun_dev, frame.payload, frame.hdr.length, NULL, 0) != 0) {
                        g_tun_gateway_ctx.drops_to_tun++;
                        (void)send_tun_fail(ctrl_io, "tun_write_failed", "failed to write packet to tun");
                        od_frame_free(&frame);
                        continue;
                    }
                    g_tun_gateway_ctx.pkts_to_tun++;
                    g_tun_gateway_ctx.bytes_to_tun += frame.hdr.length;
                } else if (frame.hdr.stream_id == 0 &&
                           (frame.hdr.type == OD_MSG_ADD_BIND || frame.hdr.type == OD_MSG_DEL_BIND ||
                            frame.hdr.type == OD_MSG_LIST_BIND || frame.hdr.type == OD_MSG_CAPS_REQ ||
                            frame.hdr.type == OD_MSG_STATUS_REQ || frame.hdr.type == OD_MSG_LIST_STREAM ||
                            frame.hdr.type == OD_MSG_CLOSE_STREAM ||
                            frame.hdr.type == OD_MSG_SNAPSHOT_REQ ||
                            frame.hdr.type == OD_MSG_TUN_CAPS_REQ || frame.hdr.type == OD_MSG_TUN_STATUS_REQ ||
                            frame.hdr.type == OD_MSG_TUN_ROUTE_ADD || frame.hdr.type == OD_MSG_TUN_ROUTE_DEL ||
                            frame.hdr.type == OD_MSG_TUN_ROUTE_LIST || frame.hdr.type == OD_MSG_TUN_POLICY_SET ||
                            frame.hdr.type == OD_MSG_TUN_POLICY_GET || frame.hdr.type == OD_MSG_TUN_SESSION_LIST ||
                            frame.hdr.type == OD_MSG_TUN_SESSION_CLOSE ||
                            frame.hdr.type == OD_MSG_TUN_KILLSWITCH_SET ||
                            frame.hdr.type == OD_MSG_TUN_MTU_SET)) {
                    char payload_all[1200];
                    const char *cmd_payload = payload_all;
                    uint8_t fail_msg = fail_msg_for_control_type(frame.hdr.type);
                    memset(payload_all, 0, sizeof(payload_all));
                    if (frame.hdr.length >= sizeof(payload_all)) {
                        const char *msg = "payload too long";
                        (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }
                    if (frame.hdr.length > 0) {
                        memcpy(payload_all, frame.payload, frame.hdr.length);
                    }
                    payload_all[frame.hdr.length] = '\0';

                    if (control_admin_policy != NULL && !control_admin_policy->enabled) {
                        const char *msg = "control admin disabled";
                        (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }
                    if (control_admin_policy != NULL && control_admin_policy->require_token &&
                        control_admin_policy->token == NULL) {
                        const char *msg = "control admin token required by policy";
                        (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }
                    if (control_admin_policy != NULL &&
                        !control_admin_rate_allow(control_admin_policy->rate_limit_per_min,
                                                  &control_admin_rate_window_ms,
                                                  &control_admin_rate_count)) {
                        const char *msg = "control admin rate limit exceeded";
                        (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }
                    if (control_admin_policy != NULL && control_admin_policy->token != NULL) {
                        char *tab = strchr(payload_all, '\t');
                        if (tab == NULL &&
                            frame.hdr.type != OD_MSG_LIST_BIND &&
                            frame.hdr.type != OD_MSG_LIST_STREAM &&
                            frame.hdr.type != OD_MSG_CAPS_REQ &&
                            frame.hdr.type != OD_MSG_STATUS_REQ &&
                            frame.hdr.type != OD_MSG_SNAPSHOT_REQ &&
                            frame.hdr.type != OD_MSG_TUN_CAPS_REQ &&
                            frame.hdr.type != OD_MSG_TUN_STATUS_REQ &&
                            frame.hdr.type != OD_MSG_TUN_ROUTE_LIST &&
                            frame.hdr.type != OD_MSG_TUN_POLICY_GET &&
                            frame.hdr.type != OD_MSG_TUN_SESSION_LIST) {
                            const char *msg = "control admin token required";
                            (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (tab != NULL) {
                            *tab = '\0';
                        }
                        if (strcmp(payload_all, control_admin_policy->token) != 0) {
                            const char *msg = "control admin token invalid";
                            (void)od_send_frame_io(ctrl_io, fail_msg, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (tab != NULL) {
                            cmd_payload = tab + 1;
                        } else {
                            cmd_payload = "";
                        }
                    }

                    if (frame.hdr.type == OD_MSG_ADD_BIND) {
                        endpoint_t listen_ep;
                        endpoint_t target_ep;
                        uint32_t bind_id = 0;
                        char err[160];
                        memset(err, 0, sizeof(err));
                        if (control_admin_policy != NULL && control_admin_policy->max_binds == 0) {
                            const char *msg = "bind operations disabled";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (control_admin_policy != NULL && control_admin_policy->max_binds > 0 &&
                            srv_bind_manager_present_count(&bind_mgr) >= control_admin_policy->max_binds) {
                            const char *msg = "max binds reached";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (parse_bind_rule_text(cmd_payload, &listen_ep, &target_ep) != 0) {
                            const char *msg = "invalid bind format";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (srv_bind_manager_add_live(&bind_mgr, &listen_ep, &target_ep, &bind_id,
                                                      err, sizeof(err)) != 0) {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, err, (uint32_t)strlen(err));
                        } else {
                            char ok[160];
                            (void)snprintf(ok, sizeof(ok), "bind_id=%lu", (unsigned long)bind_id);
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_OK, 0, 0, ok, (uint32_t)strlen(ok));
                            od_log_info("control add-bind id=%lu %s:%u -> %s:%u",
                                        (unsigned long)bind_id, listen_ep.host, (unsigned)listen_ep.port,
                                        target_ep.host, (unsigned)target_ep.port);
                        }
                    } else if (frame.hdr.type == OD_MSG_DEL_BIND) {
                        uint32_t bind_id = 0;
                        char err[160];
                        memset(err, 0, sizeof(err));
                        if (parse_u32_text(cmd_payload, &bind_id) != 0) {
                            const char *msg = "invalid bind id";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        if (srv_bind_manager_del_live(&bind_mgr, bind_id, err, sizeof(err)) != 0) {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_FAIL, 0, 0, err, (uint32_t)strlen(err));
                        } else {
                            char ok[160];
                            (void)snprintf(ok, sizeof(ok), "bind_id=%lu deleted", (unsigned long)bind_id);
                            (void)od_send_frame_io(ctrl_io, OD_MSG_BIND_OK, 0, 0, ok, (uint32_t)strlen(ok));
                            od_log_info("control del-bind id=%lu", (unsigned long)bind_id);
                        }
                    } else if (frame.hdr.type == OD_MSG_LIST_BIND) {
                        char list_payload[4096];
                        memset(list_payload, 0, sizeof(list_payload));
                        bind_list_to_text(&bind_mgr, list_payload, sizeof(list_payload));
                        (void)od_send_frame_io(ctrl_io, OD_MSG_LIST_BIND_RESP, 0, 0,
                                               list_payload, (uint32_t)strlen(list_payload));
                    } else if (frame.hdr.type == OD_MSG_CAPS_REQ) {
                        char caps_data[2048];
                        char response[3072];
                        memset(caps_data, 0, sizeof(caps_data));
                        memset(response, 0, sizeof(response));
                        if (bind_capabilities_to_text(caps_data, sizeof(caps_data),
                                                      control_admin_policy, socks_active) != 0 ||
                            build_ctrl_response(response, sizeof(response), true, "OK",
                                                "capabilities", caps_data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_CAPS_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_STATUS_REQ) {
                        char status_data[2048];
                        char response[3072];
                        memset(status_data, 0, sizeof(status_data));
                        memset(response, 0, sizeof(response));
                        if (bind_status_to_text(status_data, sizeof(status_data), &bind_mgr,
                                                streams, max_streams, socks_active, admin_active, hb,
                                                session_started_ms) != 0 ||
                            build_ctrl_response(response, sizeof(response), true, "OK",
                                                "status", status_data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STATUS_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_LIST_STREAM) {
                        char list_data[4096];
                        char response[6144];
                        memset(list_data, 0, sizeof(list_data));
                        memset(response, 0, sizeof(response));
                        if (stream_list_to_text(streams, max_streams, list_data, sizeof(list_data)) != 0 ||
                            build_ctrl_response(response, sizeof(response), true, "OK",
                                                "list-stream", list_data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_LIST_STREAM_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_CLOSE_STREAM) {
                        uint32_t stream_id = 0;
                        ssize_t sidx = -1;
                        char response[1024];
                        memset(response, 0, sizeof(response));
                        if (parse_u32_text(cmd_payload, &stream_id) != 0) {
                            const char *msg = "invalid stream id";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        sidx = find_srv_stream_by_id(streams, max_streams, stream_id);
                        if (sidx < 0) {
                            const char *msg = "stream not found";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                        (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, stream_id, NULL, 0);
                        close_srv_stream(&streams[sidx]);
                        if (build_ctrl_response(response, sizeof(response), true, "OK",
                                                "stream closed", "") != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_OK, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                        od_log_info("control close-stream id=%lu", (unsigned long)stream_id);
                    } else if (frame.hdr.type == OD_MSG_SNAPSHOT_REQ) {
                        char data[4096];
                        char response[6144];
                        memset(data, 0, sizeof(data));
                        memset(response, 0, sizeof(response));
                        if (!g_tun_gateway_ctx.active) {
                            const char *msg = "snapshot only available in gateway mode";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0,
                                                   msg, (uint32_t)strlen(msg));
                        } else if (tun_gateway_snapshot_to_text(data, sizeof(data)) != 0 ||
                                   build_ctrl_response(response, sizeof(response), true, "OK",
                                                       "snapshot", data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_STREAM_FAIL, 0, 0,
                                                   msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_SNAPSHOT_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_CAPS_REQ) {
                        char tun_data[1024];
                        char response[2048];
                        memset(tun_data, 0, sizeof(tun_data));
                        memset(response, 0, sizeof(response));
                        if (tun_capabilities_to_text(tun_data, sizeof(tun_data)) != 0 ||
                            build_ctrl_response(response, sizeof(response), true, "OK",
                                                "tun-capabilities", tun_data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_CAPS_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_STATUS_REQ) {
                        char tun_data[1024];
                        char response[2048];
                        memset(tun_data, 0, sizeof(tun_data));
                        memset(response, 0, sizeof(response));
                        if (tun_status_to_text(tun_data, sizeof(tun_data)) != 0 ||
                            build_ctrl_response(response, sizeof(response), true, "OK",
                                                "tun-status", tun_data) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_STATUS_RESP, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_ROUTE_LIST) {
                        char data[2048];
                        memset(data, 0, sizeof(data));
                        if (tun_gateway_route_list_to_text(data, sizeof(data)) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_ROUTE_LIST_RESP, 0, 0,
                                                   data, (uint32_t)strlen(data));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_ROUTE_ADD ||
                               frame.hdr.type == OD_MSG_TUN_ROUTE_DEL) {
                        char err[160];
                        char ok[256];
                        const char *verb = frame.hdr.type == OD_MSG_TUN_ROUTE_ADD ? "added" : "deleted";
                        memset(err, 0, sizeof(err));
                        memset(ok, 0, sizeof(ok));
                        if (!g_tun_gateway_ctx.active) {
                            (void)send_tun_fail(ctrl_io, "unsupported_capability", "gateway tun runtime not active");
                        } else if (tun_gateway_apply_route_op(
                                       frame.hdr.type == OD_MSG_TUN_ROUTE_ADD ? "add" : "del",
                                       cmd_payload, err, sizeof(err)) != 0) {
                            (void)send_tun_fail(ctrl_io, "route_error", err);
                        } else {
                            (void)snprintf(ok, sizeof(ok), "route %s %.220s", verb, cmd_payload);
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_OK, 0, 0,
                                                   ok, (uint32_t)strlen(ok));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_POLICY_GET) {
                        char data[2048];
                        memset(data, 0, sizeof(data));
                        if (tun_policy_cache_to_text(&g_tun_gateway_ctx.policy, data, sizeof(data)) != 0) {
                            const char *msg = "internal error";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_POLICY_RESP, 0, 0,
                                                   data, (uint32_t)strlen(data));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_POLICY_SET) {
                        char op[64];
                        const char *value = "";
                        char cmd_copy[256];
                        char *tab = NULL;
                        char err[160];
                        memset(op, 0, sizeof(op));
                        memset(cmd_copy, 0, sizeof(cmd_copy));
                        memset(err, 0, sizeof(err));
                        if (strlen(cmd_payload) >= sizeof(cmd_copy)) {
                            (void)send_tun_fail(ctrl_io, "policy_error", "policy payload too long");
                            od_frame_free(&frame);
                            continue;
                        }
                        memcpy(cmd_copy, cmd_payload, strlen(cmd_payload));
                        tab = strchr(cmd_copy, '\t');
                        if (tab != NULL) {
                            *tab = '\0';
                            value = tab + 1;
                        }
                        (void)snprintf(op, sizeof(op), "%.63s", cmd_copy);
                        if (tun_gateway_apply_policy_delta(op, value, err, sizeof(err)) != 0) {
                            (void)send_tun_fail(ctrl_io, "policy_error", err);
                        } else {
                            (void)tun_sync_policy_delta(ctrl_io,
                                                        strcmp(op, "allow-cidr-add") == 0 ? "ALLOW_CIDR_ADD" :
                                                        strcmp(op, "allow-cidr-del") == 0 ? "ALLOW_CIDR_DEL" :
                                                        strcmp(op, "allow-port-add") == 0 ? "ALLOW_PORT_ADD" :
                                                        "ALLOW_PORT_DEL",
                                                        value);
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_OK, 0, 0,
                                                   "policy updated", (uint32_t)strlen("policy updated"));
                        }
                    } else if (frame.hdr.type == OD_MSG_TUN_KILLSWITCH_SET) {
                        if (strcmp(cmd_payload, "enabled") == 0 || strcmp(cmd_payload, "on") == 0) {
                            g_tun_gateway_ctx.killswitch_manual = true;
                        } else if (strcmp(cmd_payload, "disabled") == 0 || strcmp(cmd_payload, "off") == 0) {
                            g_tun_gateway_ctx.killswitch_manual = false;
                        } else {
                            (void)send_tun_fail(ctrl_io, "invalid_killswitch", "expected enabled|disabled");
                            od_frame_free(&frame);
                            continue;
                        }
                        (void)tun_sync_killswitch(ctrl_io);
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_OK, 0, 0,
                                               cmd_payload, (uint32_t)strlen(cmd_payload));
                    } else if (is_tun_control_type(frame.hdr.type)) {
                        char response[1024];
                        memset(response, 0, sizeof(response));
                        if (build_ctrl_response(response, sizeof(response), false,
                                                "unsupported_capability",
                                                "TUN control action not implemented in T1.7",
                                                "") != 0) {
                            const char *msg = "unsupported capability";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                        } else {
                            (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0,
                                                   response, (uint32_t)strlen(response));
                        }
                    }
                }

                od_frame_free(&frame);
            } else if (meta[i].kind == POLL_KIND_LISTENER) {
                size_t lidx = meta[i].idx;
                char peer_host[NI_MAXHOST];
                uint16_t peer_port = 0;
                socket_t local_fd =
                    od_accept_with_peer(bind_mgr.items[lidx].lfd, peer_host, sizeof(peer_host), &peer_port);
                if (local_fd != OD_SOCK_INVALID) {
                    ssize_t free_idx = find_free_srv_stream(streams, max_streams);
                    char target_raw[300];
                    char deny_reason[96];
                    memset(deny_reason, 0, sizeof(deny_reason));
                    if (!od_hardening_allow_connection(hard_state, peer_host, deny_reason, sizeof(deny_reason))) {
                        od_log_warn("reject bind source=%s:%u reason=%s",
                                    peer_host, (unsigned)peer_port, deny_reason);
                        od_socket_close(local_fd);
                    } else if (free_idx < 0) {
                        od_log_warn("max streams reached (%lu), dropping new local client",
                                    (unsigned long)max_streams);
                        od_socket_close(local_fd);
                    } else if (endpoint_to_text(&bind_mgr.items[lidx].target_ep, target_raw,
                                                sizeof(target_raw)) != 0) {
                        od_socket_close(local_fd);
                    } else {
                        srv_stream_t *s = &streams[free_idx];
                        memset(s, 0, sizeof(*s));
                        s->used = true;
                        s->open_confirmed = false;
                        s->is_socks = false;
                        s->socks_reply_sent = false;
                        s->stream_id = next_stream_id++;
                        if (next_stream_id == 0) {
                            next_stream_id = 1;
                        }
                        s->local_fd = local_fd;
                        s->target = bind_mgr.items[lidx].target_ep;

                        od_log_stream("info", s->stream_id,
                                      "new local client %s:%u requesting OPEN to %s (bind_id=%lu)",
                                      peer_host, (unsigned)peer_port, target_raw,
                                      (unsigned long)bind_mgr.items[lidx].bind_id);
                        if (od_send_frame_io(ctrl_io, OD_MSG_OPEN, 0, s->stream_id, target_raw,
                                             (uint32_t)strlen(target_raw)) != 0) {
                            close_srv_stream(s);
                            free(fds);
                            free(meta);
                            goto cleanup;
                        }
                    }
                }
            } else if (meta[i].kind == POLL_KIND_SOCKS_LISTENER) {
                char peer_host[NI_MAXHOST];
                uint16_t peer_port = 0;
                socket_t local_fd = od_accept_with_peer(socks_lfd, peer_host, sizeof(peer_host), &peer_port);
                if (local_fd != OD_SOCK_INVALID) {
                    endpoint_t target_ep;
                    uint8_t rep_code = OD_SOCKS_REP_GENERAL_FAILURE;
                    ssize_t free_idx = find_free_srv_stream(streams, max_streams);
                    char target_raw[300];
                    char deny_reason[96];

                    memset(&target_ep, 0, sizeof(target_ep));
                    memset(deny_reason, 0, sizeof(deny_reason));
                    if (!od_hardening_allow_connection(hard_state, peer_host, deny_reason, sizeof(deny_reason))) {
                        od_log_warn("reject socks source=%s:%u reason=%s",
                                    peer_host, (unsigned)peer_port, deny_reason);
                        (void)od_socks_send_reply(local_fd, OD_SOCKS_REP_RULESET_DENIED);
                        od_socket_close(local_fd);
                        continue;
                    }
                    if (free_idx < 0) {
                        od_log_warn("max streams reached (%lu), dropping new SOCKS client",
                                    (unsigned long)max_streams);
                        (void)od_socks_send_reply(local_fd, OD_SOCKS_REP_GENERAL_FAILURE);
                        od_socket_close(local_fd);
                        continue;
                    }

                    if (od_socks_negotiate(local_fd, socks_opts != NULL ? socks_opts->username : NULL,
                                           socks_opts != NULL ? socks_opts->password : NULL) != 0) {
                        od_socket_close(local_fd);
                        continue;
                    }
                    if (od_socks_read_connect(local_fd, &target_ep, &rep_code) != 0) {
                        (void)od_socks_send_reply(local_fd, rep_code);
                        od_socket_close(local_fd);
                        continue;
                    }
                    if (endpoint_to_text(&target_ep, target_raw, sizeof(target_raw)) != 0) {
                        (void)od_socks_send_reply(local_fd, OD_SOCKS_REP_GENERAL_FAILURE);
                        od_socket_close(local_fd);
                        continue;
                    }

                    {
                        srv_stream_t *s = &streams[free_idx];
                        memset(s, 0, sizeof(*s));
                        s->used = true;
                        s->open_confirmed = false;
                        s->is_socks = true;
                        s->socks_reply_sent = false;
                        s->stream_id = next_stream_id++;
                        if (next_stream_id == 0) {
                            next_stream_id = 1;
                        }
                        s->local_fd = local_fd;
                        s->target = target_ep;

                        od_log_stream("info", s->stream_id,
                                      "new SOCKS CONNECT source=%s:%u to %s",
                                      peer_host, (unsigned)peer_port, target_raw);
                        if (od_send_frame_io(ctrl_io, OD_MSG_OPEN, 0, s->stream_id, target_raw,
                                             (uint32_t)strlen(target_raw)) != 0) {
                            (void)od_socks_send_reply(local_fd, OD_SOCKS_REP_GENERAL_FAILURE);
                            close_srv_stream(s);
                            free(fds);
                            free(meta);
                            goto cleanup;
                        }
                    }
                }
            } else if (meta[i].kind == POLL_KIND_KNOCK_LISTENER) {
                if (hard_state != NULL) {
                    char peer_host[NI_MAXHOST];
                    uint16_t peer_port = 0;
                    socket_t kfd = od_accept_with_peer(knock_listeners[meta[i].idx].lfd,
                                                       peer_host, sizeof(peer_host), &peer_port);
                    if (kfd != OD_SOCK_INVALID) {
                        od_hardening_on_knock(hard_state, peer_host, knock_listeners[meta[i].idx].port);
                        od_socket_close(kfd);
                    }
                }
            } else if (meta[i].kind == POLL_KIND_ADMIN_LISTENER) {
                socket_t afd = accept(admin_lfd, NULL, NULL);
                if (afd != OD_SOCK_INVALID) {
                    (void)handle_admin_client(afd, &bind_mgr, streams, max_streams, hb,
                                              socks_active, admin_active, session_started_ms,
                                              control_admin_policy, admin_token, ctrl_io);
                    od_socket_close(afd);
                }
            } else if (meta[i].kind == POLL_KIND_TUN_DEV) {
                uint8_t pkt[OD_TUN_MAX_PACKET];
                size_t pkt_len = 0;
                if (!tun_active) {
                    continue;
                }
                if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    g_tun_gateway_ctx.drops_from_tun++;
                    continue;
                }
                if (od_tun_dev_read_packet(&tun_dev, pkt, sizeof(pkt), &pkt_len, NULL, 0) != 0) {
                    g_tun_gateway_ctx.drops_from_tun++;
                    continue;
                }
                if (!packet_dst_matches_cidrs(pkt, pkt_len,
                                              (const char *const *)g_tun_gateway_ctx.route_allow.items,
                                              g_tun_gateway_ctx.route_allow.count)) {
                    g_tun_gateway_ctx.drops_from_tun++;
                    continue;
                }
                if (g_tun_gateway_ctx.killswitch_manual || !g_tun_gateway_ctx.control_connected) {
                    g_tun_gateway_ctx.drops_from_tun++;
                    continue;
                }
                if (!packet_allowed_by_runtime_policy(pkt, pkt_len)) {
                    g_tun_gateway_ctx.drops_from_tun++;
                    continue;
                }
                if (od_send_frame_io(ctrl_io, OD_MSG_TUN_PKT, 0, 0, pkt, (uint32_t)pkt_len) != 0) {
                    free(fds);
                    free(meta);
                    goto cleanup;
                }
                g_tun_gateway_ctx.pkts_from_tun++;
                g_tun_gateway_ctx.bytes_from_tun += pkt_len;
            } else if (meta[i].kind == POLL_KIND_STREAM) {
                size_t sidx = meta[i].idx;
                srv_stream_t *s = &streams[sidx];
                uint8_t buf[FORWARD_BUF_SIZE];
                int n = 0;

                if (!s->used || !s->open_confirmed) {
                    continue;
                }

                if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    close_srv_stream(s);
                    continue;
                }

                n = recv(s->local_fd, (char *)buf, (int)sizeof(buf), 0);
                if (n > 0) {
                    if (od_send_frame_io(ctrl_io, OD_MSG_DATA, 0, s->stream_id, buf, (uint32_t)n) != 0) {
                        close_srv_stream(s);
                        free(fds);
                        free(meta);
                        goto cleanup;
                    }
                    s->bytes_from_local += (uint32_t)n;
                } else if (n == 0) {
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    close_srv_stream(s);
                } else if (!od_socket_error_is_retryable(od_socket_last_error())) {
                    od_socket_log_error("recv(local)");
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    close_srv_stream(s);
                }
            }
        }

        free(fds);
        free(meta);

        if (hb_tick(ctrl_io, hb) != 0) {
            break;
        }
    }

cleanup:
    g_tun_gateway_ctx.control_connected = false;
    if (streams != NULL) {
        for (i = 0; i < max_streams; i++) {
            close_srv_stream(&streams[i]);
        }
    }
    srv_bind_manager_destroy(&bind_mgr);
    if (socks_active) {
        od_socket_close(socks_lfd);
    }
    if (admin_active) {
        od_socket_close(admin_lfd);
    }

    free(streams);
    return ret;
}

static int run_client_multiplex_loop(socket_t cfd, const od_io_t *ctrl_io, int connect_timeout_ms,
                                     const endpoint_t *allow_targets, size_t allow_target_count,
                                     size_t max_streams, hb_state_t *hb) {
    cli_stream_t *streams = NULL;
    size_t i = 0;

    streams = (cli_stream_t *)calloc(max_streams, sizeof(*streams));
    if (streams == NULL) {
        od_log_error("out of memory");
        return -1;
    }
    for (i = 0; i < max_streams; i++) {
        streams[i].target_fd = OD_SOCK_INVALID;
    }

    for (;;) {
        pollfd_t *fds = NULL;
        poll_meta_t *meta = NULL;
        size_t nfds = 0;
        size_t cap = 1 + max_streams;
        int rc = 0;

        fds = (pollfd_t *)calloc(cap, sizeof(*fds));
        meta = (poll_meta_t *)calloc(cap, sizeof(*meta));
        if (fds == NULL || meta == NULL) {
            free(fds);
            free(meta);
            od_log_error("out of memory");
            break;
        }

        fds[nfds].fd = cfd;
        fds[nfds].events = OD_SOCK_POLLIN;
        meta[nfds].kind = POLL_KIND_CONTROL;
        meta[nfds].idx = 0;
        nfds++;

        for (i = 0; i < max_streams; i++) {
            if (!streams[i].used) {
                continue;
            }
            fds[nfds].fd = streams[i].target_fd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_STREAM;
            meta[nfds].idx = i;
            nfds++;
        }

        rc = od_socket_poll(fds, (unsigned long)nfds, DEFAULT_POLL_MS);
        if (rc < 0) {
            free(fds);
            free(meta);
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(reverse-client)");
            break;
        }

        for (i = 0; i < nfds; i++) {
            if (!(fds[i].revents & (OD_SOCK_POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
                continue;
            }

            if (meta[i].kind == POLL_KIND_CONTROL) {
                od_frame_t frame;
                bool closed = false;
                memset(&frame, 0, sizeof(frame));
                if (od_recv_frame_io(ctrl_io, &frame, &closed) != 0) {
                    free(fds);
                    free(meta);
                    goto cleanup;
                }
                if (closed) {
                    od_log_warn("control channel closed by peer");
                    od_frame_free(&frame);
                    free(fds);
                    free(meta);
                    goto cleanup;
                }

                if (hb_on_frame(ctrl_io, hb, &frame) != 0) {
                    od_frame_free(&frame);
                    free(fds);
                    free(meta);
                    goto cleanup;
                }

                if (frame.hdr.type == OD_MSG_OPEN) {
                    char raw[400];
                    endpoint_t target_ep;
                    ssize_t free_idx = -1;
                    cli_stream_t *s = NULL;

                    if (frame.hdr.length >= sizeof(raw)) {
                        const char *msg = "target too long";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id, msg,
                                               (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }

                    memcpy(raw, frame.payload, frame.hdr.length);
                    raw[frame.hdr.length] = '\0';
                    memset(&target_ep, 0, sizeof(target_ep));
                    if (parse_endpoint_text(raw, &target_ep) != 0) {
                        const char *msg = "invalid target";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id, msg,
                                               (uint32_t)strlen(msg));
                        od_frame_free(&frame);
                        continue;
                    }

                    if (!is_target_allowed(&target_ep, allow_targets, allow_target_count)) {
                        const char *msg = "target not allowed";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id, msg,
                                               (uint32_t)strlen(msg));
                        od_log_stream("warn", frame.hdr.stream_id, "OPEN denied by allow-target policy (%s)", raw);
                        od_frame_free(&frame);
                        continue;
                    }

                    free_idx = find_free_cli_stream(streams, max_streams);
                    if (free_idx < 0) {
                        const char *msg = "capacity reached";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id, msg,
                                               (uint32_t)strlen(msg));
                        od_log_warn("max streams reached (%lu), rejecting OPEN", (unsigned long)max_streams);
                        od_frame_free(&frame);
                        continue;
                    }

                    s = &streams[free_idx];
                    memset(s, 0, sizeof(*s));
                    {
                        char reason[160];
                        memset(reason, 0, sizeof(reason));
                        s->target_fd = od_connect_to_target_ex(&target_ep, connect_timeout_ms,
                                                               reason, sizeof(reason));
                        if (s->target_fd == OD_SOCK_INVALID) {
                            const char *msg = (reason[0] != '\0') ? reason : "connect failed";
                            (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id, msg,
                                                   (uint32_t)strlen(msg));
                            od_frame_free(&frame);
                            continue;
                        }
                    }

                    s->used = true;
                    s->stream_id = frame.hdr.stream_id;
                    s->target = target_ep;
                    od_log_stream("info", s->stream_id, "connected target %s", raw);
                    if (od_send_frame_io(ctrl_io, OD_MSG_OPEN_OK, 0, s->stream_id, NULL, 0) != 0) {
                        close_cli_stream(s);
                        od_frame_free(&frame);
                        free(fds);
                        free(meta);
                        goto cleanup;
                    }
                } else if (frame.hdr.type == OD_MSG_DATA || frame.hdr.type == OD_MSG_CLOSE) {
                    ssize_t sidx = find_cli_stream_by_id(streams, max_streams, frame.hdr.stream_id);
                    if (sidx >= 0) {
                        cli_stream_t *s = &streams[sidx];
                        if (frame.hdr.type == OD_MSG_DATA) {
                            if (socket_write_all(s->target_fd, frame.payload, frame.hdr.length) != 0) {
                                od_log_stream("warn", s->stream_id, "target write failed");
                                (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                                close_cli_stream(s);
                            } else {
                                s->bytes_to_target += frame.hdr.length;
                            }
                        } else {
                            od_log_stream("info", s->stream_id, "close from server");
                            close_cli_stream(s);
                        }
                    }
                }

                od_frame_free(&frame);
            } else if (meta[i].kind == POLL_KIND_STREAM) {
                size_t sidx = meta[i].idx;
                cli_stream_t *s = &streams[sidx];
                uint8_t buf[FORWARD_BUF_SIZE];
                int n = 0;

                if (!s->used) {
                    continue;
                }

                if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    close_cli_stream(s);
                    continue;
                }

                n = recv(s->target_fd, (char *)buf, (int)sizeof(buf), 0);
                if (n > 0) {
                    if (od_send_frame_io(ctrl_io, OD_MSG_DATA, 0, s->stream_id, buf, (uint32_t)n) != 0) {
                        close_cli_stream(s);
                        free(fds);
                        free(meta);
                        goto cleanup;
                    }
                    s->bytes_from_target += (uint32_t)n;
                } else if (n == 0) {
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    od_log_stream("info", s->stream_id, "target EOF");
                    close_cli_stream(s);
                } else if (!od_socket_error_is_retryable(od_socket_last_error())) {
                    od_socket_log_error("recv(target)");
                    (void)od_send_frame_io(ctrl_io, OD_MSG_CLOSE, 0, s->stream_id, NULL, 0);
                    close_cli_stream(s);
                }
            }
        }

        free(fds);
        free(meta);

        if (hb_tick(ctrl_io, hb) != 0) {
            break;
        }
    }

cleanup:
    for (i = 0; i < max_streams; i++) {
        close_cli_stream(&streams[i]);
    }
    free(streams);
    return -1;
}

int od_run_reverse_server(const endpoint_t *control_listen_ep, const od_bind_rule_t *bind_rules,
                          size_t bind_count, const od_socks_server_opts_t *socks_opts,
                          size_t max_streams, const char *token,
                          const od_hardening_options_t *hardening_opts,
                          const od_admin_server_opts_t *admin_opts,
                          const od_control_admin_policy_t *control_admin_policy,
                          const od_tls_options_t *tls_opts,
                          int heartbeat_ms, int heartbeat_timeout_ms, bool verbose) {
    socket_t lfd = OD_SOCK_INVALID;
    socket_t cfd = OD_SOCK_INVALID;
    od_hardening_state_t *hard_state = NULL;
    knock_listener_t *knock_listeners = NULL;
    size_t knock_count = 0;
    char hard_err[160];
    od_tls_mode_t tls_mode = OD_TLS_MODE_DISABLED;

    if (tls_opts != NULL) {
        tls_mode = tls_opts->mode;
    }
    if (tls_mode == OD_TLS_MODE_REQUIRED && !od_tls_is_available()) {
        od_log_error("TLS mode is required but this build has no TLS backend");
        return 1;
    }
    memset(hard_err, 0, sizeof(hard_err));
    if (od_hardening_init(&hard_state, hardening_opts, hard_err, sizeof(hard_err)) != 0) {
        od_log_error("hardening init failed: %s", hard_err);
        return 1;
    }

    lfd = od_open_listener(control_listen_ep);
    if (lfd == OD_SOCK_INVALID) {
        od_hardening_free(hard_state);
        return 1;
    }
    knock_listeners = open_knock_listeners(control_listen_ep->host, hard_state, &knock_count);
    if (od_hardening_has_knock(hard_state) && knock_count > 0 && knock_listeners == NULL) {
        od_log_error("failed to initialize knock listeners");
        od_socket_close(lfd);
        od_hardening_free(hard_state);
        return 1;
    }
    if (knock_listeners != NULL) {
        size_t i = 0;
        for (i = 0; i < knock_count; i++) {
            if (!knock_listeners[i].active) {
                od_log_error("knock listener unavailable on port %u", (unsigned)knock_listeners[i].port);
                od_socket_close(lfd);
                while (i > 0) {
                    i--;
                    if (knock_listeners[i].active) {
                        od_socket_close(knock_listeners[i].lfd);
                    }
                }
                free(knock_listeners);
                od_hardening_free(hard_state);
                return 1;
            }
        }
    }

    od_log_info("reverse-server listening control on %s:%u (tls=%s backend=%s)",
                control_listen_ep->host, (unsigned)control_listen_ep->port,
                od_tls_mode_name(tls_mode), od_tls_backend_name());

    for (;;) {
        hb_state_t hb;
        od_io_t ctrl_io;
        od_socket_io_ctx_t sock_io;
        od_tls_state_t *tls_state = NULL;
        char tls_err[256];
        bool control_ready = false;
        bool accepted = false;

        memset(&ctrl_io, 0, sizeof(ctrl_io));
        memset(&sock_io, 0, sizeof(sock_io));
        memset(tls_err, 0, sizeof(tls_err));
        cfd = OD_SOCK_INVALID;

        for (;;) {
            pollfd_t *fds = NULL;
            poll_meta_t *meta = NULL;
            size_t nfds = 0;
            size_t cap = 1 + knock_count;
            size_t i = 0;
            int rc = 0;

            fds = (pollfd_t *)calloc(cap, sizeof(*fds));
            meta = (poll_meta_t *)calloc(cap, sizeof(*meta));
            if (fds == NULL || meta == NULL) {
                free(fds);
                free(meta);
                od_log_error("out of memory");
                accepted = false;
                break;
            }

            fds[nfds].fd = lfd;
            fds[nfds].events = OD_SOCK_POLLIN;
            meta[nfds].kind = POLL_KIND_CONTROL;
            meta[nfds].idx = 0;
            nfds++;

            for (i = 0; i < knock_count; i++) {
                if (!knock_listeners[i].active) {
                    continue;
                }
                fds[nfds].fd = knock_listeners[i].lfd;
                fds[nfds].events = OD_SOCK_POLLIN;
                meta[nfds].kind = POLL_KIND_KNOCK_LISTENER;
                meta[nfds].idx = i;
                nfds++;
            }

            rc = od_socket_poll(fds, (unsigned long)nfds, DEFAULT_POLL_MS);
            if (rc < 0) {
                free(fds);
                free(meta);
                if (od_socket_error_is_retryable(od_socket_last_error())) {
                    continue;
                }
                od_socket_log_error("poll(control-listen)");
                accepted = false;
                break;
            }

            for (i = 0; i < nfds; i++) {
                if (!(fds[i].revents & OD_SOCK_POLLIN)) {
                    continue;
                }
                if (meta[i].kind == POLL_KIND_KNOCK_LISTENER) {
                    char peer_host[NI_MAXHOST];
                    uint16_t peer_port = 0;
                    socket_t kfd = od_accept_with_peer(knock_listeners[meta[i].idx].lfd,
                                                       peer_host, sizeof(peer_host), &peer_port);
                    if (kfd != OD_SOCK_INVALID) {
                        od_hardening_on_knock(hard_state, peer_host, knock_listeners[meta[i].idx].port);
                        od_socket_close(kfd);
                    }
                } else if (meta[i].kind == POLL_KIND_CONTROL) {
                    char peer_host[NI_MAXHOST];
                    uint16_t peer_port = 0;
                    char deny_reason[96];
                    cfd = od_accept_with_peer(lfd, peer_host, sizeof(peer_host), &peer_port);
                    if (cfd == OD_SOCK_INVALID) {
                        if (!od_socket_error_is_retryable(od_socket_last_error())) {
                            od_socket_log_error("accept(control)");
                        }
                        continue;
                    }
                    memset(deny_reason, 0, sizeof(deny_reason));
                    if (!od_hardening_allow_connection(hard_state, peer_host,
                                                       deny_reason, sizeof(deny_reason))) {
                        od_log_warn("reject control source=%s:%u reason=%s",
                                    peer_host, (unsigned)peer_port, deny_reason);
                        od_socket_close(cfd);
                        cfd = OD_SOCK_INVALID;
                        continue;
                    }
                    od_log_info("control client connected source=%s:%u", peer_host, (unsigned)peer_port);
                    accepted = true;
                    break;
                }
            }

            free(fds);
            free(meta);
            if (accepted) {
                break;
            }
        }
        if (!accepted || cfd == OD_SOCK_INVALID) {
            break;
        }
        if (tls_mode == OD_TLS_MODE_REQUIRED) {
            if (od_tls_wrap_server_socket(cfd, tls_opts, &ctrl_io, &tls_state, tls_err,
                                          sizeof(tls_err)) != 0) {
                od_log_warn("TLS handshake failed: %s", tls_err);
            } else {
                od_log_info("TLS session established (reverse-server)");
                control_ready = true;
            }
        } else {
            od_io_init_socket(&ctrl_io, &sock_io, cfd);
            control_ready = true;
        }

        if (control_ready && do_server_handshake(&ctrl_io, token) == 0) {
            hb_init(&hb, heartbeat_ms, heartbeat_timeout_ms, verbose);
            if (bind_count == 0 && (socks_opts == NULL || socks_opts->listen_ep == NULL) &&
                (admin_opts == NULL || admin_opts->listen_ep == NULL) &&
                control_admin_policy == NULL) {
                (void)run_server_control_only_loop(cfd, &ctrl_io, &hb,
                                                   hard_state, knock_listeners, knock_count);
            } else {
                (void)run_server_multiplex_loop(cfd, &ctrl_io, bind_rules, bind_count,
                                                socks_opts, max_streams, &hb,
                                                hard_state, knock_listeners, knock_count,
                                                admin_opts != NULL ? admin_opts->listen_ep : NULL,
                                                admin_opts != NULL ? admin_opts->token : NULL,
                                                control_admin_policy);
            }
        }

        od_tls_state_free(tls_state);
        od_socket_close(cfd);
        cfd = OD_SOCK_INVALID;
        od_log_warn("control session closed");
    }

    od_socket_close(lfd);
    if (knock_listeners != NULL) {
        size_t i = 0;
        for (i = 0; i < knock_count; i++) {
            if (knock_listeners[i].active) {
                od_socket_close(knock_listeners[i].lfd);
            }
        }
    }
    free(knock_listeners);
    od_hardening_free(hard_state);
    return 0;
}

static int run_client_control_actions(const od_io_t *ctrl_io, const od_ctrl_client_opts_t *ctrl_opts) {
    size_t i = 0;
    if (ctrl_opts == NULL || ctrl_opts->action_count == 0) {
        return 0;
    }

    for (i = 0; i < ctrl_opts->action_count; i++) {
        const od_ctrl_action_t *a = &ctrl_opts->actions[i];
        uint8_t msg = 0;
        uint8_t expect = 0;
        uint8_t fail = 0;
        const void *payload = NULL;
        uint32_t payload_len = 0;
        char payload_buf[1400];
        od_frame_t resp;
        bool closed = false;
        char text[4096];

        memset(&resp, 0, sizeof(resp));
        memset(text, 0, sizeof(text));
        memset(payload_buf, 0, sizeof(payload_buf));

        if (a->type == OD_CTRL_ACTION_LIST_BIND) {
            msg = OD_MSG_LIST_BIND;
            expect = OD_MSG_LIST_BIND_RESP;
            fail = OD_MSG_BIND_FAIL;
        } else if (a->type == OD_CTRL_ACTION_ADD_BIND) {
            msg = OD_MSG_ADD_BIND;
            expect = OD_MSG_BIND_OK;
            fail = OD_MSG_BIND_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", ctrl_opts->admin_token, a->value);
                payload = payload_buf;
                payload_len = (uint32_t)strlen(payload_buf);
            } else {
                payload = a->value;
                payload_len = (uint32_t)strlen(a->value);
            }
        } else if (a->type == OD_CTRL_ACTION_DEL_BIND) {
            msg = OD_MSG_DEL_BIND;
            expect = OD_MSG_BIND_OK;
            fail = OD_MSG_BIND_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", ctrl_opts->admin_token, a->value);
                payload = payload_buf;
                payload_len = (uint32_t)strlen(payload_buf);
            } else {
                payload = a->value;
                payload_len = (uint32_t)strlen(a->value);
            }
        } else if (a->type == OD_CTRL_ACTION_CAPABILITIES) {
            msg = OD_MSG_CAPS_REQ;
            expect = OD_MSG_CAPS_RESP;
            fail = OD_MSG_STREAM_FAIL;
        } else if (a->type == OD_CTRL_ACTION_STATUS) {
            msg = OD_MSG_STATUS_REQ;
            expect = OD_MSG_STATUS_RESP;
            fail = OD_MSG_STREAM_FAIL;
        } else if (a->type == OD_CTRL_ACTION_LIST_STREAM) {
            msg = OD_MSG_LIST_STREAM;
            expect = OD_MSG_LIST_STREAM_RESP;
            fail = OD_MSG_STREAM_FAIL;
        } else if (a->type == OD_CTRL_ACTION_CLOSE_STREAM) {
            msg = OD_MSG_CLOSE_STREAM;
            expect = OD_MSG_STREAM_OK;
            fail = OD_MSG_STREAM_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", ctrl_opts->admin_token, a->value);
                payload = payload_buf;
                payload_len = (uint32_t)strlen(payload_buf);
            } else {
                payload = a->value;
                payload_len = (uint32_t)strlen(a->value);
            }
        } else if (a->type == OD_CTRL_ACTION_TUN_ROUTE_LIST) {
            msg = OD_MSG_TUN_ROUTE_LIST;
            expect = OD_MSG_TUN_ROUTE_LIST_RESP;
            fail = OD_MSG_TUN_FAIL;
        } else if (a->type == OD_CTRL_ACTION_TUN_ROUTE_ADD ||
                   a->type == OD_CTRL_ACTION_TUN_ROUTE_DEL) {
            msg = (a->type == OD_CTRL_ACTION_TUN_ROUTE_ADD) ? OD_MSG_TUN_ROUTE_ADD : OD_MSG_TUN_ROUTE_DEL;
            expect = OD_MSG_TUN_OK;
            fail = OD_MSG_TUN_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", ctrl_opts->admin_token, a->value);
                payload = payload_buf;
                payload_len = (uint32_t)strlen(payload_buf);
            } else {
                payload = a->value;
                payload_len = (uint32_t)strlen(a->value);
            }
        } else if (a->type == OD_CTRL_ACTION_TUN_POLICY_SHOW) {
            msg = OD_MSG_TUN_POLICY_GET;
            expect = OD_MSG_TUN_POLICY_RESP;
            fail = OD_MSG_TUN_FAIL;
        } else if (a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_ADD ||
                   a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_DEL ||
                   a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_ADD ||
                   a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_DEL) {
            const char *op =
                (a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_ADD) ? "allow-cidr-add" :
                (a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_DEL) ? "allow-cidr-del" :
                (a->type == OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_ADD) ? "allow-port-add" :
                "allow-port-del";
            msg = OD_MSG_TUN_POLICY_SET;
            expect = OD_MSG_TUN_OK;
            fail = OD_MSG_TUN_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s\t%s",
                         ctrl_opts->admin_token, op, a->value);
            } else {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", op, a->value);
            }
            payload = payload_buf;
            payload_len = (uint32_t)strlen(payload_buf);
        } else if (a->type == OD_CTRL_ACTION_TUN_KILLSWITCH) {
            msg = OD_MSG_TUN_KILLSWITCH_SET;
            expect = OD_MSG_TUN_OK;
            fail = OD_MSG_TUN_FAIL;
            if (ctrl_opts->admin_token != NULL) {
                snprintf(payload_buf, sizeof(payload_buf), "%s\t%s", ctrl_opts->admin_token, a->value);
                payload = payload_buf;
                payload_len = (uint32_t)strlen(payload_buf);
            } else {
                payload = a->value;
                payload_len = (uint32_t)strlen(a->value);
            }
        } else if (a->type == OD_CTRL_ACTION_SNAPSHOT) {
            msg = OD_MSG_SNAPSHOT_REQ;
            expect = OD_MSG_SNAPSHOT_RESP;
            fail = OD_MSG_STREAM_FAIL;
        } else {
            continue;
        }
        if ((a->type == OD_CTRL_ACTION_LIST_BIND ||
             a->type == OD_CTRL_ACTION_CAPABILITIES ||
             a->type == OD_CTRL_ACTION_STATUS ||
             a->type == OD_CTRL_ACTION_LIST_STREAM ||
             a->type == OD_CTRL_ACTION_TUN_ROUTE_LIST ||
             a->type == OD_CTRL_ACTION_TUN_POLICY_SHOW ||
             a->type == OD_CTRL_ACTION_SNAPSHOT) &&
            ctrl_opts->admin_token != NULL) {
            snprintf(payload_buf, sizeof(payload_buf), "%s", ctrl_opts->admin_token);
            payload = payload_buf;
            payload_len = (uint32_t)strlen(payload_buf);
        }

        if (od_send_frame_io(ctrl_io, msg, 0, 0, payload, payload_len) != 0) {
            return -1;
        }

        for (;;) {
            if (od_recv_frame_io(ctrl_io, &resp, &closed) != 0) {
                return -1;
            }
            if (closed) {
                return -1;
            }
            if (resp.hdr.type == OD_MSG_PING) {
                if (od_send_frame_io(ctrl_io, OD_MSG_PONG, 0, 0, NULL, 0) != 0) {
                    od_frame_free(&resp);
                    return -1;
                }
                od_frame_free(&resp);
                continue;
            }
            if (resp.hdr.type == fail) {
                frame_payload_to_text(&resp, text, sizeof(text));
                od_log_warn("control action failed: %s", text);
                od_frame_free(&resp);
                return -1;
            }
            if (resp.hdr.type == expect) {
                frame_payload_to_text(&resp, text, sizeof(text));
                if (a->type == OD_CTRL_ACTION_LIST_BIND) {
                    od_log_info("control list-bind:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_CAPABILITIES) {
                    od_log_info("control capabilities:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_STATUS) {
                    od_log_info("control status:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_LIST_STREAM) {
                    od_log_info("control list-stream:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_TUN_ROUTE_LIST) {
                    od_log_info("control route-list:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_TUN_POLICY_SHOW) {
                    od_log_info("control policy-show:\n%s", text);
                } else if (a->type == OD_CTRL_ACTION_SNAPSHOT) {
                    od_log_info("control snapshot:\n%s", text);
                } else {
                    od_log_info("control action ok: %s", text);
                }
                od_frame_free(&resp);
                break;
            }
            od_frame_free(&resp);
        }
    }

    return 0;
}

typedef struct {
    runtime_string_list_t allow_cidrs;
    runtime_string_list_t allow_ports;
    bool killswitch_enabled;
} tun_agent_runtime_state_t;

#ifndef _WIN32
static int tun_agent_runtime_init(tun_agent_runtime_state_t *state,
                                  const od_tun_agent_runtime_opts_t *tun_opts) {
    if (state == NULL) {
        return -1;
    }
    memset(state, 0, sizeof(*state));
    if (tun_opts != NULL) {
        if (runtime_string_list_copy_from_raw(&state->allow_cidrs, tun_opts->allow_cidrs,
                                              tun_opts->allow_cidr_count) != 0 ||
            runtime_string_list_copy_from_raw(&state->allow_ports, tun_opts->allow_ports,
                                              tun_opts->allow_port_count) != 0) {
            runtime_string_list_free(&state->allow_cidrs);
            runtime_string_list_free(&state->allow_ports);
            return -1;
        }
    }
    state->killswitch_enabled = false;
    return 0;
}

static void tun_agent_runtime_free(tun_agent_runtime_state_t *state) {
    if (state == NULL) {
        return;
    }
    runtime_string_list_free(&state->allow_cidrs);
    runtime_string_list_free(&state->allow_ports);
    memset(state, 0, sizeof(*state));
}

static int tun_agent_policy_to_text(const tun_agent_runtime_state_t *state, char *out, size_t out_sz) {
    tun_policy_cache_t cache;
    memset(&cache, 0, sizeof(cache));
    cache.known = true;
    if (state != NULL) {
        cache.allow_cidrs = state->allow_cidrs;
        cache.allow_ports = state->allow_ports;
    }
    return tun_policy_cache_to_text(&cache, out, out_sz);
}

static int tun_agent_apply_policy_cmd(tun_agent_runtime_state_t *state, const char *payload) {
    char copy[256];
    char *tab = NULL;
    const char *value = "";
    if (state == NULL || payload == NULL || payload[0] == '\0' || strlen(payload) >= sizeof(copy)) {
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", payload);
    if (strcmp(copy, "RESET") == 0) {
        runtime_string_list_free(&state->allow_cidrs);
        runtime_string_list_free(&state->allow_ports);
        return 0;
    }
    tab = strchr(copy, '\t');
    if (tab != NULL) {
        *tab = '\0';
        value = tab + 1;
    }
    if (strcmp(copy, "ALLOW_CIDR_ADD") == 0) {
        return runtime_string_list_add(&state->allow_cidrs, value);
    }
    if (strcmp(copy, "ALLOW_CIDR_DEL") == 0) {
        return runtime_string_list_remove(&state->allow_cidrs, value);
    }
    if (strcmp(copy, "ALLOW_PORT_ADD") == 0) {
        return runtime_string_list_add(&state->allow_ports, value);
    }
    if (strcmp(copy, "ALLOW_PORT_DEL") == 0) {
        return runtime_string_list_remove(&state->allow_ports, value);
    }
    return -1;
}

static int tun_agent_caps_to_text(const od_tun_agent_runtime_opts_t *tun_opts, char *out, size_t out_sz) {
    size_t used = 0;
    if (appendf_line(out, out_sz, &used, "proto_version=%u\n", (unsigned)ODY_VERSION) != 0 ||
        append_line(out, out_sz, &used, "mode=tun-agent\n") != 0 ||
        appendf_line(out, out_sz, &used, "agent_name=%s\n",
                     (tun_opts != NULL && tun_opts->agent_name != NULL) ? tun_opts->agent_name : "default") != 0 ||
        appendf_line(out, out_sz, &used, "allow_cidr_count=%lu\n",
                     (unsigned long)(tun_opts != NULL ? tun_opts->allow_cidr_count : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "allow_port_count=%lu\n",
                     (unsigned long)(tun_opts != NULL ? tun_opts->allow_port_count : 0)) != 0 ||
        append_line(out, out_sz, &used, "default_deny=true\n") != 0 ||
        append_line(out, out_sz, &used,
                    "tun_actions=tun_caps_req,tun_status_req,tun_route_list,tun_policy_set,tun_policy_get,tun_killswitch_set,tun_pkt\n") != 0) {
        return -1;
    }
    return 0;
}

static int tun_agent_route_list_to_text(const tun_agent_runtime_state_t *state, char *out, size_t out_sz) {
    size_t used = 0;
    return runtime_string_list_append_text(state != NULL ? &state->allow_cidrs : NULL,
                                           "route", out, out_sz, &used);
}

static int tun_agent_status_to_text(const od_tun_agent_runtime_opts_t *tun_opts,
                                    const tun_agent_runtime_state_t *state,
                                    uint64_t session_started_ms,
                                    const tun_agent_stats_t *stats,
                                    char *out, size_t out_sz) {
    uint64_t now = now_ms();
    size_t used = 0;
    if (append_line(out, out_sz, &used, "mode=tun-agent\n") != 0 ||
        append_line(out, out_sz, &used, "runtime=dataplane_mvp\n") != 0 ||
        append_line(out, out_sz, &used, "default_deny=true\n") != 0 ||
        appendf_line(out, out_sz, &used, "allow_cidr_count=%lu\n",
                     (unsigned long)(state != NULL ? state->allow_cidrs.count :
                                     (tun_opts != NULL ? tun_opts->allow_cidr_count : 0))) != 0 ||
        appendf_line(out, out_sz, &used, "allow_port_count=%lu\n",
                     (unsigned long)(state != NULL ? state->allow_ports.count :
                                     (tun_opts != NULL ? tun_opts->allow_port_count : 0))) != 0 ||
        appendf_line(out, out_sz, &used, "killswitch_enabled=%s\n",
                     (state != NULL && state->killswitch_enabled) ? "true" : "false") != 0 ||
        appendf_line(out, out_sz, &used, "session_uptime_ms=%llu\n",
                     (unsigned long long)(now >= session_started_ms ? (now - session_started_ms) : 0)) != 0 ||
        append_line(out, out_sz, &used, "active_streams=0\n") != 0 ||
        appendf_line(out, out_sz, &used, "pkts_in=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->pkts_in : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "pkts_out=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->pkts_out : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "bytes_in=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->bytes_in : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "bytes_out=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->bytes_out : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "drops_policy=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->drops_policy : 0)) != 0 ||
        appendf_line(out, out_sz, &used, "drops_parse=%llu\n",
                     (unsigned long long)(stats != NULL ? stats->drops_parse : 0)) != 0) {
        return -1;
    }
    return 0;
}

static int run_tun_agent_control_loop(socket_t cfd, const od_io_t *ctrl_io, hb_state_t *hb,
                                      const od_tun_agent_runtime_opts_t *tun_opts) {
    uint64_t session_started_ms = now_ms();
    tun_agent_stats_t stats;
    tun_agent_runtime_state_t runtime_state;
    od_tun_dev_t agent_tun;
    bool tun_l3_active = false;
    nfds_t nfds = 1;
    char tun_err[256];

    memset(&stats, 0, sizeof(stats));
    memset(&agent_tun, 0, sizeof(agent_tun));
    agent_tun.fd = -1;
    memset(tun_err, 0, sizeof(tun_err));

    if (tun_agent_runtime_init(&runtime_state, tun_opts) != 0) {
        od_log_error("tun-agent runtime init failed");
        return -1;
    }

    if (tun_opts != NULL && tun_opts->agent_tun_cidr != NULL) {
        const char *tname = (tun_opts->agent_tun_name != NULL) ? tun_opts->agent_tun_name : "ody_agent0";
        int tmtu = (tun_opts->agent_tun_mtu > 0) ? tun_opts->agent_tun_mtu : OD_TUN_DEFAULT_MTU;
        if (od_tun_dev_open(&agent_tun, tname, "169.254.0.1/32", tmtu, tun_err, sizeof(tun_err)) != 0) {
            od_log_error("tun-agent TUN open failed: %s", tun_err);
            tun_agent_runtime_free(&runtime_state);
            return -1;
        }
        if (od_tun_add_route(tun_opts->agent_tun_cidr, agent_tun.ifname, tun_err, sizeof(tun_err)) != 0) {
            od_log_error("tun-agent route add failed: %s", tun_err);
            od_tun_dev_close(&agent_tun, true);
            tun_agent_runtime_free(&runtime_state);
            return -1;
        }
        if (od_tun_enable_ip_forward(tun_err, sizeof(tun_err)) != 0) {
            od_log_error("tun-agent ip_forward failed: %s", tun_err);
            od_tun_dev_close(&agent_tun, true);
            tun_agent_runtime_free(&runtime_state);
            return -1;
        }
        if (od_tun_enable_proxy_arp("all", tun_err, sizeof(tun_err)) != 0) {
            od_log_error("tun-agent proxy_arp failed: %s", tun_err);
            od_tun_dev_close(&agent_tun, true);
            tun_agent_runtime_free(&runtime_state);
            return -1;
        }
        tun_l3_active = true;
        nfds = 2;
        od_log_info("tun-agent L3 dataplane active: %s route=%s mtu=%d",
                    agent_tun.ifname, tun_opts->agent_tun_cidr, agent_tun.mtu);
    }

    for (;;) {
        pollfd_t fds[2];
        int rc = 0;
        memset(fds, 0, sizeof(fds));
        fds[0].fd = cfd;
        fds[0].events = OD_SOCK_POLLIN;
        if (tun_l3_active) {
            fds[1].fd = agent_tun.fd;
            fds[1].events = OD_SOCK_POLLIN;
        }

        rc = od_socket_poll(fds, nfds, DEFAULT_POLL_MS);
        if (rc < 0) {
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(tun-agent)");
            goto fail;
        }

        if (rc > 0 && (fds[0].revents & OD_SOCK_POLLIN)) {
            od_frame_t frame;
            bool closed = false;
            memset(&frame, 0, sizeof(frame));
            if (od_recv_frame_io(ctrl_io, &frame, &closed) != 0) {
                goto fail;
            }
            if (closed) {
                od_log_warn("tun-agent control channel closed by peer");
                goto fail;
            }
            if (hb_on_frame(ctrl_io, hb, &frame) != 0) {
                od_frame_free(&frame);
                goto fail;
            }

            if (frame.hdr.type == OD_MSG_OPEN) {
                const char *msg = "tun-agent mode does not support OPEN";
                (void)od_send_frame_io(ctrl_io, OD_MSG_OPEN_FAIL, 0, frame.hdr.stream_id,
                                       msg, (uint32_t)strlen(msg));
                od_frame_free(&frame);
                continue;
            }

            if (frame.hdr.stream_id == 0) {
                if (frame.hdr.type == OD_MSG_TUN_CAPS_REQ) {
                    char data[2048];
                    char response[3072];
                    memset(data, 0, sizeof(data));
                    memset(response, 0, sizeof(response));
                    if (tun_agent_caps_to_text(tun_opts, data, sizeof(data)) != 0 ||
                        build_ctrl_response(response, sizeof(response), true, "OK",
                                            "tun-capabilities", data) != 0) {
                        const char *msg = "internal error";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                    } else {
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_CAPS_RESP, 0, 0,
                                               response, (uint32_t)strlen(response));
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_STATUS_REQ) {
                    char data[2048];
                    char response[3072];
                    memset(data, 0, sizeof(data));
                    memset(response, 0, sizeof(response));
                    if (tun_agent_status_to_text(tun_opts, &runtime_state, session_started_ms, &stats,
                                                 data, sizeof(data)) != 0 ||
                        build_ctrl_response(response, sizeof(response), true, "OK",
                                            "tun-status", data) != 0) {
                        const char *msg = "internal error";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                    } else {
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_STATUS_RESP, 0, 0,
                                               response, (uint32_t)strlen(response));
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_ROUTE_LIST) {
                    char data[2048];
                    char response[3072];
                    memset(data, 0, sizeof(data));
                    memset(response, 0, sizeof(response));
                    if (tun_agent_route_list_to_text(&runtime_state, data, sizeof(data)) != 0 ||
                        build_ctrl_response(response, sizeof(response), true, "OK",
                                            "tun-route-list", data) != 0) {
                        const char *msg = "internal error";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                    } else {
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_ROUTE_LIST_RESP, 0, 0,
                                               response, (uint32_t)strlen(response));
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_POLICY_GET) {
                    char data[2048];
                    memset(data, 0, sizeof(data));
                    if (tun_agent_policy_to_text(&runtime_state, data, sizeof(data)) != 0) {
                        const char *msg = "internal error";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                    } else {
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_POLICY_RESP, 0, 0,
                                               data, (uint32_t)strlen(data));
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_POLICY_SET) {
                    char payload_buf[256];
                    memset(payload_buf, 0, sizeof(payload_buf));
                    if (frame.hdr.length == 0 || frame.payload == NULL ||
                        frame.hdr.length >= sizeof(payload_buf)) {
                        stats.drops_policy++;
                    } else {
                        memcpy(payload_buf, frame.payload, frame.hdr.length);
                        payload_buf[frame.hdr.length] = '\0';
                        if (tun_agent_apply_policy_cmd(&runtime_state, payload_buf) != 0) {
                            stats.drops_policy++;
                        }
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_KILLSWITCH_SET) {
                    char state[32];
                    memset(state, 0, sizeof(state));
                    frame_payload_to_text(&frame, state, sizeof(state));
                    if (strcmp(state, "enabled") == 0) {
                        runtime_state.killswitch_enabled = true;
                    } else if (strcmp(state, "disabled") == 0) {
                        runtime_state.killswitch_enabled = false;
                    } else {
                        stats.drops_policy++;
                    }
                } else if (frame.hdr.type == OD_MSG_TUN_PKT) {
                    stats.pkts_in++;
                    stats.bytes_in += frame.hdr.length;
                    if (runtime_state.killswitch_enabled) {
                        stats.drops_policy++;
                        (void)send_tun_fail(ctrl_io, "killswitch_enabled", "tun-agent killswitch blocks packet");
                    } else if (frame.hdr.length == 0 || frame.hdr.length > OD_TUN_MAX_PACKET) {
                        stats.drops_parse++;
                        (void)send_tun_fail(ctrl_io, "invalid_packet", "invalid tun packet length");
                    } else if (!packet_allowed_by_specs(frame.payload, frame.hdr.length,
                                                        (const char *const *)runtime_state.allow_cidrs.items,
                                                        runtime_state.allow_cidrs.count,
                                                        (const char *const *)runtime_state.allow_ports.items,
                                                        runtime_state.allow_ports.count)) {
                        stats.drops_policy++;
                        (void)send_tun_fail(ctrl_io, "policy_denied",
                                            "packet blocked by tun-agent allowlist");
                    } else if (tun_l3_active) {
                        if (od_tun_dev_write_packet(&agent_tun, frame.payload, frame.hdr.length, NULL, 0) != 0) {
                            stats.drops_parse++;
                        } else {
                            stats.pkts_out++;
                            stats.bytes_out += frame.hdr.length;
                        }
                    } else {
                        if (od_send_frame_io(ctrl_io, OD_MSG_TUN_PKT, 0, 0,
                                             frame.payload, frame.hdr.length) != 0) {
                            od_frame_free(&frame);
                            goto fail;
                        }
                        stats.pkts_out++;
                        stats.bytes_out += frame.hdr.length;
                    }
                } else if (is_tun_control_type(frame.hdr.type)) {
                    char response[1024];
                    memset(response, 0, sizeof(response));
                    if (build_ctrl_response(response, sizeof(response), false,
                                            "unsupported_capability",
                                            "TUN control action not implemented in T1.7",
                                            "") != 0) {
                        const char *msg = "unsupported capability";
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
                    } else {
                        (void)od_send_frame_io(ctrl_io, OD_MSG_TUN_FAIL, 0, 0,
                                               response, (uint32_t)strlen(response));
                    }
                }
            }

            od_frame_free(&frame);
        }

        if (tun_l3_active && rc > 0 && (fds[1].revents & OD_SOCK_POLLIN)) {
            uint8_t pkt[OD_TUN_MAX_PACKET];
            size_t pkt_len = 0;
            if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                stats.drops_parse++;
            } else if (od_tun_dev_read_packet(&agent_tun, pkt, sizeof(pkt), &pkt_len, NULL, 0) != 0) {
                stats.drops_parse++;
            } else if (runtime_state.killswitch_enabled) {
                stats.drops_policy++;
            } else if (!packet_return_allowed_by_specs(pkt, pkt_len,
                                                       (const char *const *)runtime_state.allow_cidrs.items,
                                                       runtime_state.allow_cidrs.count,
                                                       (const char *const *)runtime_state.allow_ports.items,
                                                       runtime_state.allow_ports.count)) {
                stats.drops_policy++;
            } else {
                if (od_send_frame_io(ctrl_io, OD_MSG_TUN_PKT, 0, 0, pkt, (uint32_t)pkt_len) != 0) {
                    goto fail;
                }
                stats.pkts_out++;
                stats.bytes_out += pkt_len;
                stats.pkts_in++;
                stats.bytes_in += pkt_len;
            }
        }

        if (hb_tick(ctrl_io, hb) != 0) {
            goto fail;
        }
    }

fail:
    if (tun_l3_active) {
        od_tun_dev_close(&agent_tun, true);
    }
    tun_agent_runtime_free(&runtime_state);
    return -1;
}
#endif /* !_WIN32 */

void od_reverse_set_tun_gateway_ctx(int tun_fd, const char *const *route_allow, size_t route_allow_count) {
    runtime_string_list_free(&g_tun_gateway_ctx.route_allow);
    tun_gateway_reset_policy_cache();
    memset(&g_tun_gateway_ctx, 0, sizeof(g_tun_gateway_ctx));
    g_tun_gateway_ctx.active = (tun_fd >= 0);
    g_tun_gateway_ctx.tun_fd = tun_fd;
    g_tun_gateway_ctx.control_connected = false;
    g_tun_gateway_ctx.killswitch_manual = false;
    (void)runtime_string_list_copy_from_raw(&g_tun_gateway_ctx.route_allow, route_allow, route_allow_count);
}

void od_reverse_clear_tun_gateway_ctx(void) {
    runtime_string_list_free(&g_tun_gateway_ctx.route_allow);
    tun_gateway_reset_policy_cache();
    memset(&g_tun_gateway_ctx, 0, sizeof(g_tun_gateway_ctx));
    g_tun_gateway_ctx.tun_fd = -1;
}

#ifndef _WIN32
int od_run_tun_agent(const endpoint_t *connect_ep, const char *token,
                     const od_tun_agent_runtime_opts_t *tun_opts,
                     int connect_timeout_ms, const od_knock_plan_t *knock_plan,
                     const od_tls_options_t *tls_opts,
                     int heartbeat_timeout_ms, bool verbose) {
    int heartbeat_ms = heartbeat_timeout_ms / 3;
    int backoff_ms = 1000;
    od_tls_mode_t tls_mode = OD_TLS_MODE_DISABLED;

    if (tls_opts != NULL) {
        tls_mode = tls_opts->mode;
    }
    if (tls_mode == OD_TLS_MODE_REQUIRED && !od_tls_is_available()) {
        od_log_error("TLS mode is required but this build has no TLS backend");
        return 1;
    }
    seed_prng_once();
    if (heartbeat_ms < 1000) {
        heartbeat_ms = 1000;
    }

    for (;;) {
        if (knock_plan != NULL && knock_plan->port_count > 0) {
            int wait_ms = 1000;
            if (od_run_knock(knock_plan) != 0) {
                wait_ms = backoff_with_jitter_ms(backoff_ms);
                od_log_warn("tun-agent knock failed, retrying in %d ms", wait_ms);
                sleep_ms(wait_ms);
                if (backoff_ms < 30000) {
                    backoff_ms *= 2;
                    if (backoff_ms > 30000) {
                        backoff_ms = 30000;
                    }
                }
                continue;
            }
        }

        socket_t cfd = od_connect_to_target(connect_ep, connect_timeout_ms);
        hb_state_t hb;
        od_io_t ctrl_io;
        od_socket_io_ctx_t sock_io;
        od_tls_state_t *tls_state = NULL;
        char tls_err[256];
        bool control_ready = false;
        int wait_ms = 1000;

        memset(&ctrl_io, 0, sizeof(ctrl_io));
        memset(&sock_io, 0, sizeof(sock_io));
        memset(tls_err, 0, sizeof(tls_err));

        if (cfd == OD_SOCK_INVALID) {
            wait_ms = backoff_with_jitter_ms(backoff_ms);
            od_log_warn("tun-agent connect failed, retrying in %d ms", wait_ms);
            sleep_ms(wait_ms);
            if (backoff_ms < 30000) {
                backoff_ms *= 2;
                if (backoff_ms > 30000) {
                    backoff_ms = 30000;
                }
            }
            continue;
        }

        od_log_info("tun-agent connected to gateway %s:%u (tls=%s backend=%s)",
                    connect_ep->host, (unsigned)connect_ep->port,
                    od_tls_mode_name(tls_mode), od_tls_backend_name());

        if (tls_mode == OD_TLS_MODE_REQUIRED) {
            if (od_tls_wrap_client_socket(cfd, tls_opts, &ctrl_io, &tls_state, tls_err,
                                          sizeof(tls_err)) != 0) {
                od_log_warn("tun-agent TLS handshake failed: %s", tls_err);
            } else {
                od_log_info("tun-agent TLS session established");
                control_ready = true;
            }
        } else {
            od_io_init_socket(&ctrl_io, &sock_io, cfd);
            control_ready = true;
        }

        if (control_ready && do_client_handshake(&ctrl_io, token) == 0) {
            hb_init(&hb, heartbeat_ms, heartbeat_timeout_ms, verbose);
            (void)run_tun_agent_control_loop(cfd, &ctrl_io, &hb, tun_opts);
            backoff_ms = 1000;
        }

        od_tls_state_free(tls_state);
        od_socket_close(cfd);
        wait_ms = backoff_with_jitter_ms(backoff_ms);
        od_log_warn("tun-agent control disconnected, reconnecting in %d ms", wait_ms);
        sleep_ms(wait_ms);
        if (backoff_ms < 30000) {
            backoff_ms *= 2;
            if (backoff_ms > 30000) {
                backoff_ms = 30000;
            }
        }
    }
}
#else /* _WIN32 */
int od_run_tun_agent(const endpoint_t *connect_ep, const char *token,
                     const od_tun_agent_runtime_opts_t *tun_opts,
                     int connect_timeout_ms, const od_knock_plan_t *knock_plan,
                     const od_tls_options_t *tls_opts,
                     int heartbeat_timeout_ms, bool verbose) {
    (void)connect_ep; (void)token; (void)tun_opts; (void)connect_timeout_ms;
    (void)knock_plan; (void)tls_opts; (void)heartbeat_timeout_ms; (void)verbose;
    od_log_error("tun-agent mode is not supported on Windows");
    return -1;
}
#endif /* !_WIN32 */

int od_run_reverse_client(const endpoint_t *connect_ep, const endpoint_t *allow_targets,
                          size_t allow_target_count, size_t max_streams,
                          const char *token, int connect_timeout_ms,
                          const od_knock_plan_t *knock_plan,
                          const od_ctrl_client_opts_t *ctrl_opts,
                          const od_tls_options_t *tls_opts,
                          int heartbeat_timeout_ms, bool verbose) {
    int heartbeat_ms = heartbeat_timeout_ms / 3;
    int backoff_ms = 1000;
    od_tls_mode_t tls_mode = OD_TLS_MODE_DISABLED;

    if (tls_opts != NULL) {
        tls_mode = tls_opts->mode;
    }
    if (tls_mode == OD_TLS_MODE_REQUIRED && !od_tls_is_available()) {
        od_log_error("TLS mode is required but this build has no TLS backend");
        return 1;
    }

    seed_prng_once();
    if (heartbeat_ms < 1000) {
        heartbeat_ms = 1000;
    }

    for (;;) {
        if (knock_plan != NULL && knock_plan->port_count > 0) {
            int wait_ms = 1000;
            if (od_run_knock(knock_plan) != 0) {
                wait_ms = backoff_with_jitter_ms(backoff_ms);
                od_log_warn("reverse-client knock failed, retrying in %d ms", wait_ms);
                sleep_ms(wait_ms);
                if (backoff_ms < 30000) {
                    backoff_ms *= 2;
                    if (backoff_ms > 30000) {
                        backoff_ms = 30000;
                    }
                }
                continue;
            }
        }

        socket_t cfd = od_connect_to_target(connect_ep, connect_timeout_ms);
        hb_state_t hb;
        od_io_t ctrl_io;
        od_socket_io_ctx_t sock_io;
        od_tls_state_t *tls_state = NULL;
        char tls_err[256];
        int wait_ms = 1000;
        bool control_ready = false;

        memset(&ctrl_io, 0, sizeof(ctrl_io));
        memset(&sock_io, 0, sizeof(sock_io));
        memset(tls_err, 0, sizeof(tls_err));

        if (cfd == OD_SOCK_INVALID) {
            wait_ms = backoff_with_jitter_ms(backoff_ms);
            od_log_warn("reverse-client connect failed, retrying in %d ms", wait_ms);
            sleep_ms(wait_ms);
            if (backoff_ms < 30000) {
                backoff_ms *= 2;
                if (backoff_ms > 30000) {
                    backoff_ms = 30000;
                }
            }
            continue;
        }

        od_log_info("connected to reverse-server %s:%u (tls=%s backend=%s)",
                    connect_ep->host, (unsigned)connect_ep->port,
                    od_tls_mode_name(tls_mode), od_tls_backend_name());

        if (tls_mode == OD_TLS_MODE_REQUIRED) {
            if (od_tls_wrap_client_socket(cfd, tls_opts, &ctrl_io, &tls_state, tls_err,
                                          sizeof(tls_err)) != 0) {
                od_log_warn("TLS handshake failed: %s", tls_err);
            } else {
                od_log_info("TLS session established (reverse-client)");
                control_ready = true;
            }
        } else {
            od_io_init_socket(&ctrl_io, &sock_io, cfd);
            control_ready = true;
        }

        if (control_ready && do_client_handshake(&ctrl_io, token) == 0) {
            if (run_client_control_actions(&ctrl_io, ctrl_opts) != 0) {
                if (ctrl_opts != NULL && ctrl_opts->exit_after_actions) {
                    od_log_warn("control actions failed");
                    od_tls_state_free(tls_state);
                    od_socket_close(cfd);
                    return 1;
                }
            } else if (ctrl_opts != NULL && ctrl_opts->action_count > 0 && ctrl_opts->exit_after_actions) {
                od_log_info("control actions completed, exiting");
                od_tls_state_free(tls_state);
                od_socket_close(cfd);
                return 0;
            }

            hb_init(&hb, heartbeat_ms, heartbeat_timeout_ms, verbose);
            (void)run_client_multiplex_loop(cfd, &ctrl_io, connect_timeout_ms, allow_targets,
                                            allow_target_count, max_streams, &hb);
            backoff_ms = 1000;
        }

        od_tls_state_free(tls_state);
        od_socket_close(cfd);
        wait_ms = backoff_with_jitter_ms(backoff_ms);
        od_log_warn("control disconnected, reconnecting in %d ms", wait_ms);
        sleep_ms(wait_ms);
        if (backoff_ms < 30000) {
            backoff_ms *= 2;
            if (backoff_ms > 30000) {
                backoff_ms = 30000;
            }
        }
    }
}
