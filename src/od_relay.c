#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#include "od_log.h"
#include "od_relay.h"

#define IO_BUF_SIZE 16384
#define RELAY_POLL_MS 250

typedef struct {
    uint8_t data[IO_BUF_SIZE];
    size_t off;
    size_t len;
    bool eof;
    bool half_closed;
} stream_buf_t;

typedef struct {
    socket_t client_fd;
    socket_t remote_fd;
    bool verbose;
    uint32_t stream_id;
} relay_worker_ctx_t;

typedef struct {
    socket_t lfd;
    uint16_t port;
    bool active;
} relay_knock_listener_t;

static bool buf_empty(const stream_buf_t *b) {
    return b->off == b->len;
}

static int do_read(socket_t src_fd, stream_buf_t *dst, socket_t shutdown_fd) {
    int n = 0;
    int err = 0;

    if (!buf_empty(dst)) {
        return 0;
    }

    n = recv(src_fd, (char *)dst->data, (int)sizeof(dst->data), 0);
    if (n > 0) {
        dst->off = 0;
        dst->len = (size_t)n;
        return 0;
    }
    if (n == 0) {
        dst->eof = true;
        if (buf_empty(dst) && !dst->half_closed) {
            if (shutdown(shutdown_fd, OD_SOCK_SHUT_WR) != 0) {
                err = od_socket_last_error();
                if (!od_socket_error_is_notconn(err)) {
                    od_socket_log_error("shutdown");
                    return -1;
                }
            }
            dst->half_closed = true;
        }
        return 0;
    }

    err = od_socket_last_error();
    if (od_socket_error_is_retryable(err)) {
        return 0;
    }

    od_socket_log_error("recv");
    return -1;
}

static int do_write(socket_t dst_fd, stream_buf_t *src) {
    int n = 0;
    int err = 0;
    size_t pending = 0;

    if (buf_empty(src)) {
        if (src->eof && !src->half_closed) {
            if (shutdown(dst_fd, OD_SOCK_SHUT_WR) != 0) {
                err = od_socket_last_error();
                if (!od_socket_error_is_notconn(err)) {
                    od_socket_log_error("shutdown");
                    return -1;
                }
            }
            src->half_closed = true;
        }
        return 0;
    }

    pending = src->len - src->off;
    n = send(dst_fd, (const char *)(src->data + src->off), (int)pending, 0);
    if (n > 0) {
        src->off += (size_t)n;
        if (src->off == src->len) {
            src->off = 0;
            src->len = 0;
            if (src->eof && !src->half_closed) {
                if (shutdown(dst_fd, OD_SOCK_SHUT_WR) != 0) {
                    err = od_socket_last_error();
                    if (!od_socket_error_is_notconn(err)) {
                        od_socket_log_error("shutdown");
                        return -1;
                    }
                }
                src->half_closed = true;
            }
        }
        return 0;
    }

    err = od_socket_last_error();
    if (od_socket_error_is_retryable(err)) {
        return 0;
    }

    od_socket_log_error("send");
    return -1;
}

int od_relay_bidirectional(socket_t left_fd, socket_t right_fd, bool verbose) {
    stream_buf_t left_to_right;
    stream_buf_t right_to_left;
    pollfd_t fds[2];
    int rc = 0;

    memset(&left_to_right, 0, sizeof(left_to_right));
    memset(&right_to_left, 0, sizeof(right_to_left));

    if (od_set_nonblocking(left_fd) < 0 || od_set_nonblocking(right_fd) < 0) {
        od_socket_log_error("set_nonblocking");
        return -1;
    }

    for (;;) {
        memset(fds, 0, sizeof(fds));
        fds[0].fd = left_fd;
        fds[1].fd = right_fd;

        if (!left_to_right.eof && buf_empty(&left_to_right)) {
            fds[0].events |= OD_SOCK_POLLIN;
        }
        if (!right_to_left.eof && buf_empty(&right_to_left)) {
            fds[1].events |= OD_SOCK_POLLIN;
        }
        if (!buf_empty(&right_to_left)) {
            fds[0].events |= OD_SOCK_POLLOUT;
        }
        if (!buf_empty(&left_to_right)) {
            fds[1].events |= OD_SOCK_POLLOUT;
        }

        if (fds[0].events == 0 && fds[1].events == 0) {
            break;
        }

        rc = od_socket_poll(fds, 2UL, -1);
        if (rc < 0) {
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll");
            return -1;
        }

        if (fds[0].revents & OD_SOCK_POLLIN) {
            if (do_read(left_fd, &left_to_right, right_fd) < 0) {
                return -1;
            }
        }
        if (fds[1].revents & OD_SOCK_POLLIN) {
            if (do_read(right_fd, &right_to_left, left_fd) < 0) {
                return -1;
            }
        }

        if (fds[0].revents & OD_SOCK_POLLOUT) {
            if (do_write(left_fd, &right_to_left) < 0) {
                return -1;
            }
        }
        if (fds[1].revents & OD_SOCK_POLLOUT) {
            if (do_write(right_fd, &left_to_right) < 0) {
                return -1;
            }
        }

        if ((fds[0].revents & (POLLERR | POLLNVAL)) || (fds[1].revents & (POLLERR | POLLNVAL))) {
            return -1;
        }
    }

    if (verbose) {
        od_log_info("Relay session finished cleanly");
    }

    return 0;
}

#ifdef _WIN32
static DWORD WINAPI relay_worker_thread(LPVOID arg) {
    relay_worker_ctx_t *ctx = (relay_worker_ctx_t *)arg;
    (void)od_relay_bidirectional(ctx->client_fd, ctx->remote_fd, ctx->verbose);
    od_log_stream("info", ctx->stream_id, "closed");
    od_socket_close(ctx->client_fd);
    od_socket_close(ctx->remote_fd);
    free(ctx);
    return 0;
}

static int spawn_relay_worker(socket_t cfd, socket_t rfd, bool verbose, uint32_t stream_id) {
    relay_worker_ctx_t *ctx = (relay_worker_ctx_t *)calloc(1, sizeof(*ctx));
    HANDLE th = NULL;
    if (ctx == NULL) {
        od_log_error("Out of memory");
        return -1;
    }

    ctx->client_fd = cfd;
    ctx->remote_fd = rfd;
    ctx->verbose = verbose;
    ctx->stream_id = stream_id;

    th = CreateThread(NULL, 0, relay_worker_thread, ctx, 0, NULL);
    if (th == NULL) {
        od_log_error("CreateThread failed (%lu)", GetLastError());
        free(ctx);
        return -1;
    }

    CloseHandle(th);
    return 0;
}
#else
static int spawn_relay_worker(socket_t cfd, socket_t rfd, bool verbose, uint32_t stream_id) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        (void)od_relay_bidirectional(cfd, rfd, verbose);
        od_log_stream("info", stream_id, "closed");
        od_socket_close(cfd);
        od_socket_close(rfd);
        _exit(0);
    }

    return 0;
}
#endif

static relay_knock_listener_t *open_knock_listeners(const char *host, od_hardening_state_t *hard_state,
                                                    size_t *out_count) {
    relay_knock_listener_t *arr = NULL;
    size_t count = 0;
    size_t i = 0;

    if (out_count != NULL) {
        *out_count = 0;
    }
    if (hard_state == NULL || !od_hardening_has_knock(hard_state)) {
        return NULL;
    }

    count = od_hardening_knock_count(hard_state);
    arr = (relay_knock_listener_t *)calloc(count, sizeof(*arr));
    if (arr == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        endpoint_t ep;
        memset(&ep, 0, sizeof(ep));
        snprintf(ep.host, sizeof(ep.host), "%s", host);
        ep.port = od_hardening_knock_port_at(hard_state, i);
        arr[i].port = ep.port;
        arr[i].lfd = od_open_listener(&ep);
        arr[i].active = (arr[i].lfd != OD_SOCK_INVALID);
        if (!arr[i].active) {
            od_log_warn("failed knock listener %s:%u", ep.host, (unsigned)ep.port);
        } else {
            od_log_info("knock listener on %s:%u", ep.host, (unsigned)ep.port);
        }
    }

    if (out_count != NULL) {
        *out_count = count;
    }
    return arr;
}

int od_run_relay(const endpoint_t *listen_ep, const endpoint_t *target_ep, int connect_timeout_ms,
                 const od_hardening_options_t *hardening_opts, bool verbose) {
    socket_t lfd = OD_SOCK_INVALID;
    od_hardening_state_t *hard_state = NULL;
    relay_knock_listener_t *knock_listeners = NULL;
    size_t knock_count = 0;
    uint32_t stream_id = 0;
    char hard_err[160];
    int ret = 0;

    memset(hard_err, 0, sizeof(hard_err));
    if (od_hardening_init(&hard_state, hardening_opts, hard_err, sizeof(hard_err)) != 0) {
        od_log_error("hardening init failed: %s", hard_err);
        return 1;
    }

    lfd = od_open_listener(listen_ep);
    if (lfd == OD_SOCK_INVALID) {
        od_hardening_free(hard_state);
        return 1;
    }
    knock_listeners = open_knock_listeners(listen_ep->host, hard_state, &knock_count);
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

    od_log_info("Listening on %s:%u", listen_ep->host, (unsigned)listen_ep->port);
    od_log_info("Forwarding to %s:%u", target_ep->host, (unsigned)target_ep->port);

    for (;;) {
        pollfd_t *fds = NULL;
        size_t *knock_map = NULL;
        size_t nfds = 0;
        size_t i = 0;
        int rc = 0;
        socket_t cfd = OD_SOCK_INVALID;
        socket_t rfd = OD_SOCK_INVALID;
        char peer_host[NI_MAXHOST];
        uint16_t peer_port = 0;

        fds = (pollfd_t *)calloc(1 + knock_count, sizeof(*fds));
        knock_map = (size_t *)calloc(1 + knock_count, sizeof(*knock_map));
        if (fds == NULL || knock_map == NULL) {
            free(fds);
            free(knock_map);
            od_log_error("out of memory");
            ret = 1;
            break;
        }

        fds[nfds].fd = lfd;
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

        rc = od_socket_poll(fds, (unsigned long)nfds, RELAY_POLL_MS);
        if (rc < 0) {
            free(fds);
            free(knock_map);
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(relay)");
            ret = 1;
            break;
        }

        if (rc > 0) {
            for (i = 1; i < nfds; i++) {
                if (!(fds[i].revents & OD_SOCK_POLLIN)) {
                    continue;
                }
                cfd = od_accept_with_peer(fds[i].fd, peer_host, sizeof(peer_host), &peer_port);
                if (cfd != OD_SOCK_INVALID) {
                    od_hardening_on_knock(hard_state, peer_host, knock_listeners[knock_map[i]].port);
                    od_socket_close(cfd);
                }
            }
        }

        if (!(fds[0].revents & OD_SOCK_POLLIN)) {
            free(fds);
            free(knock_map);
            continue;
        }
        free(fds);
        free(knock_map);

        cfd = od_accept_with_peer(lfd, peer_host, sizeof(peer_host), &peer_port);
        if (cfd == OD_SOCK_INVALID) {
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("accept");
            ret = 1;
            break;
        }

        {
            char deny_reason[96];
            memset(deny_reason, 0, sizeof(deny_reason));
            if (!od_hardening_allow_connection(hard_state, peer_host, deny_reason, sizeof(deny_reason))) {
                od_log_warn("relay rejected source=%s:%u reason=%s", peer_host, (unsigned)peer_port, deny_reason);
                od_socket_close(cfd);
                continue;
            }
        }

        stream_id++;
        od_log_stream("info", stream_id, "new client %s:%u", peer_host, (unsigned)peer_port);

        rfd = od_connect_to_target(target_ep, connect_timeout_ms);
        if (rfd == OD_SOCK_INVALID) {
            od_log_stream("warn", stream_id, "dropping client (target unavailable)");
            od_socket_close(cfd);
            continue;
        }

        if (spawn_relay_worker(cfd, rfd, verbose, stream_id) < 0) {
            od_socket_close(cfd);
            od_socket_close(rfd);
            continue;
        }

#ifndef _WIN32
        od_socket_close(cfd);
        od_socket_close(rfd);
#endif
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
    return ret;
}

/* ── UDP relay ─────────────────────────────────────────────────── */

#define UDP_MAX_CLIENTS 256
#define UDP_BUF_SIZE    65535
#define UDP_POLL_MS     500

typedef struct {
    struct sockaddr_in client_addr;
    socket_t remote_fd;
    uint64_t last_active_ms;
    bool in_use;
} udp_nat_entry_t;

static uint64_t udp_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

static int udp_nat_find(udp_nat_entry_t *table, size_t cap,
                        const struct sockaddr_in *addr) {
    size_t i;
    for (i = 0; i < cap; i++) {
        if (table[i].in_use &&
            table[i].client_addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            table[i].client_addr.sin_port == addr->sin_port) {
            return (int)i;
        }
    }
    return -1;
}

static int udp_nat_alloc(udp_nat_entry_t *table, size_t cap) {
    size_t i;
    for (i = 0; i < cap; i++) {
        if (!table[i].in_use) {
            return (int)i;
        }
    }
    return -1;
}

static void udp_nat_expire(udp_nat_entry_t *table, size_t cap, uint64_t timeout_ms) {
    size_t i;
    uint64_t now = udp_now_ms();
    for (i = 0; i < cap; i++) {
        if (table[i].in_use && (now - table[i].last_active_ms) > timeout_ms) {
            od_socket_close(table[i].remote_fd);
            table[i].in_use = false;
        }
    }
}

static size_t udp_nat_active(const udp_nat_entry_t *table, size_t cap) {
    size_t count = 0;
    size_t i;
    for (i = 0; i < cap; i++) {
        if (table[i].in_use) {
            count++;
        }
    }
    return count;
}

int od_run_udp_relay(const endpoint_t *listen_ep, const endpoint_t *target_ep,
                     int timeout_ms, const od_hardening_options_t *hardening_opts,
                     bool verbose) {
    socket_t lfd = OD_SOCK_INVALID;
    od_hardening_state_t *hard_state = NULL;
    udp_nat_entry_t nat_table[UDP_MAX_CLIENTS];
    uint8_t buf[UDP_BUF_SIZE];
    char hard_err[160];
    int ret = 0;

    memset(nat_table, 0, sizeof(nat_table));
    memset(hard_err, 0, sizeof(hard_err));

    if (od_hardening_init(&hard_state, hardening_opts, hard_err, sizeof(hard_err)) != 0) {
        od_log_error("hardening init failed: %s", hard_err);
        return 1;
    }

    lfd = od_open_udp_socket(listen_ep, true);
    if (lfd == OD_SOCK_INVALID) {
        od_hardening_free(hard_state);
        return 1;
    }

    if (od_set_nonblocking(lfd) < 0) {
        od_socket_log_error("set_nonblocking(udp listener)");
        od_socket_close(lfd);
        od_hardening_free(hard_state);
        return 1;
    }

    od_log_info("UDP relay listening on %s:%u", listen_ep->host, (unsigned)listen_ep->port);
    od_log_info("UDP relay forwarding to %s:%u (timeout %dms)",
                target_ep->host, (unsigned)target_ep->port, timeout_ms);

    for (;;) {
        size_t active = udp_nat_active(nat_table, UDP_MAX_CLIENTS);
        size_t nfds = 1 + active;
        pollfd_t *fds = (pollfd_t *)calloc(nfds, sizeof(*fds));
        int *fd_to_nat = (int *)calloc(nfds, sizeof(*fd_to_nat));
        size_t slot = 1;
        size_t i;
        int rc;

        if (fds == NULL || fd_to_nat == NULL) {
            free(fds);
            free(fd_to_nat);
            od_log_error("out of memory");
            ret = 1;
            break;
        }

        fds[0].fd = lfd;
        fds[0].events = OD_SOCK_POLLIN;
        fd_to_nat[0] = -1;

        for (i = 0; i < UDP_MAX_CLIENTS; i++) {
            if (nat_table[i].in_use) {
                fds[slot].fd = nat_table[i].remote_fd;
                fds[slot].events = OD_SOCK_POLLIN;
                fd_to_nat[slot] = (int)i;
                slot++;
            }
        }

        rc = od_socket_poll(fds, (unsigned long)nfds, UDP_POLL_MS);
        if (rc < 0) {
            free(fds);
            free(fd_to_nat);
            if (od_socket_error_is_retryable(od_socket_last_error())) {
                continue;
            }
            od_socket_log_error("poll(udp relay)");
            ret = 1;
            break;
        }

        if (rc == 0) {
            free(fds);
            free(fd_to_nat);
            udp_nat_expire(nat_table, UDP_MAX_CLIENTS, (uint64_t)timeout_ms);
            continue;
        }

        if (fds[0].revents & OD_SOCK_POLLIN) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            int n = recvfrom(lfd, (char *)buf, sizeof(buf), 0,
                             (struct sockaddr *)&from_addr, &from_len);
            if (n > 0) {
                char peer_ip[NI_MAXHOST];
                int idx;
                memset(peer_ip, 0, sizeof(peer_ip));
                getnameinfo((struct sockaddr *)&from_addr, from_len,
                            peer_ip, sizeof(peer_ip), NULL, 0, NI_NUMERICHOST);

                {
                    char deny_reason[96];
                    memset(deny_reason, 0, sizeof(deny_reason));
                    if (!od_hardening_allow_connection(hard_state, peer_ip,
                                                      deny_reason, sizeof(deny_reason))) {
                        if (verbose) {
                            od_log_warn("udp relay rejected source=%s reason=%s",
                                        peer_ip, deny_reason);
                        }
                        goto after_listener;
                    }
                }

                idx = udp_nat_find(nat_table, UDP_MAX_CLIENTS, &from_addr);
                if (idx < 0) {
                    socket_t rfd = od_open_udp_socket(target_ep, false);
                    if (rfd == OD_SOCK_INVALID) {
                        od_log_warn("udp relay: cannot open socket to target for %s", peer_ip);
                        goto after_listener;
                    }
                    if (od_set_nonblocking(rfd) < 0) {
                        od_socket_close(rfd);
                        goto after_listener;
                    }
                    idx = udp_nat_alloc(nat_table, UDP_MAX_CLIENTS);
                    if (idx < 0) {
                        udp_nat_expire(nat_table, UDP_MAX_CLIENTS, (uint64_t)timeout_ms);
                        idx = udp_nat_alloc(nat_table, UDP_MAX_CLIENTS);
                    }
                    if (idx < 0) {
                        od_log_warn("udp relay: NAT table full, dropping from %s", peer_ip);
                        od_socket_close(rfd);
                        goto after_listener;
                    }
                    nat_table[idx].client_addr = from_addr;
                    nat_table[idx].remote_fd = rfd;
                    nat_table[idx].in_use = true;
                    if (verbose) {
                        od_log_info("udp relay: new session slot=%d from=%s:%u",
                                    idx, peer_ip, (unsigned)ntohs(from_addr.sin_port));
                    }
                }
                nat_table[idx].last_active_ms = udp_now_ms();
                send(nat_table[idx].remote_fd, (const char *)buf, n, 0);
            }
        }
after_listener:

        for (slot = 1; slot < nfds; slot++) {
            if (!(fds[slot].revents & OD_SOCK_POLLIN)) {
                continue;
            }
            {
                int nat_idx = fd_to_nat[slot];
                int n;
                if (nat_idx < 0 || !nat_table[nat_idx].in_use) {
                    continue;
                }
                n = recv(nat_table[nat_idx].remote_fd, (char *)buf, sizeof(buf), 0);
                if (n > 0) {
                    nat_table[nat_idx].last_active_ms = udp_now_ms();
                    sendto(lfd, (const char *)buf, n, 0,
                           (struct sockaddr *)&nat_table[nat_idx].client_addr,
                           sizeof(nat_table[nat_idx].client_addr));
                }
            }
        }

        free(fds);
        free(fd_to_nat);
        udp_nat_expire(nat_table, UDP_MAX_CLIENTS, (uint64_t)timeout_ms);
    }

    {
        size_t i;
        for (i = 0; i < UDP_MAX_CLIENTS; i++) {
            if (nat_table[i].in_use) {
                od_socket_close(nat_table[i].remote_fd);
            }
        }
    }
    od_socket_close(lfd);
    od_hardening_free(hard_state);
    return ret;
}
