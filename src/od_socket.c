#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "od_log.h"
#include "od_socket.h"

int od_socket_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        od_log_error("WSAStartup failed");
        return -1;
    }
#endif
    return 0;
}

void od_socket_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int od_socket_last_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool od_socket_error_is_retryable(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINTR;
#else
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
#endif
}

bool od_socket_error_is_notconn(int err) {
#ifdef _WIN32
    return err == WSAENOTCONN;
#else
    return err == ENOTCONN;
#endif
}

static bool od_socket_error_is_inprogress(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
#else
    return err == EINPROGRESS;
#endif
}

static int od_socket_timeout_error_code(void) {
#ifdef _WIN32
    return WSAETIMEDOUT;
#else
    return ETIMEDOUT;
#endif
}

static const char *od_socket_error_to_string(int err, char *buf, size_t buf_sz) {
#ifdef _WIN32
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = 0;
    if (buf == NULL || buf_sz == 0) {
        return "";
    }
    len = FormatMessageA(flags, NULL, (DWORD)err, 0, buf, (DWORD)buf_sz, NULL);
    if (len == 0) {
        (void)snprintf(buf, buf_sz, "WSA error %d", err);
        return buf;
    }
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
        buf[len - 1] = '\0';
        len--;
    }
    return buf;
#else
    const char *msg = NULL;
    if (buf == NULL || buf_sz == 0) {
        return "";
    }
    msg = strerror(err);
    if (msg == NULL) {
        (void)snprintf(buf, buf_sz, "errno %d", err);
    } else {
        (void)snprintf(buf, buf_sz, "%s", msg);
    }
    return buf;
#endif
}

void od_socket_log_error(const char *ctx) {
#ifdef _WIN32
    od_log_error("%s failed (WSA error=%d)", ctx, WSAGetLastError());
#else
    perror(ctx);
#endif
}

int od_socket_close(socket_t fd) {
#ifdef _WIN32
    return closesocket(fd);
#else
    return close(fd);
#endif
}

int od_socket_poll(pollfd_t *fds, unsigned long count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(fds, count, timeout_ms);
#else
    return poll(fds, (nfds_t)count, timeout_ms);
#endif
}

int od_set_nonblocking(socket_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(fd, FIONBIO, &mode) != 0) {
        return -1;
    }
    return 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
#endif
}

socket_t od_accept_with_peer(socket_t lfd, char *peer_host, size_t peer_host_sz, uint16_t *peer_port) {
    struct sockaddr_storage peer_addr;
    socklen_t peer_len = (socklen_t)sizeof(peer_addr);
    socket_t cfd = accept(lfd, (struct sockaddr *)&peer_addr, &peer_len);
    char serv[NI_MAXSERV];

    if (peer_host != NULL && peer_host_sz > 0) {
        snprintf(peer_host, peer_host_sz, "unknown");
    }
    if (peer_port != NULL) {
        *peer_port = 0;
    }

    if (cfd == OD_SOCK_INVALID) {
        return OD_SOCK_INVALID;
    }

    memset(serv, 0, sizeof(serv));
    if (peer_host != NULL && peer_host_sz > 0 &&
        getnameinfo((struct sockaddr *)&peer_addr, peer_len, peer_host, (socklen_t)peer_host_sz,
                    serv, (socklen_t)sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        snprintf(peer_host, peer_host_sz, "unknown");
    }
    if (peer_port != NULL && serv[0] != '\0') {
        unsigned long p = strtoul(serv, NULL, 10);
        if (p <= 65535UL) {
            *peer_port = (uint16_t)p;
        }
    }

    return cfd;
}

static int od_socket_get_so_error(socket_t fd, int *out_err) {
    int soerr = 0;
#ifdef _WIN32
    int soerr_len = (int)sizeof(soerr);
#else
    socklen_t soerr_len = (socklen_t)sizeof(soerr);
#endif

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &soerr_len) != 0) {
        return -1;
    }
    *out_err = soerr;
    return 0;
}

static void od_addr_to_numeric(const struct sockaddr *sa, socklen_t sa_len,
                               char *host, size_t host_len, char *serv, size_t serv_len) {
    int rc = getnameinfo(sa, sa_len, host, (socklen_t)host_len, serv, (socklen_t)serv_len,
                         NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        (void)snprintf(host, host_len, "?");
        (void)snprintf(serv, serv_len, "?");
    }
}

static int od_socket_connect_with_timeout(socket_t fd, const struct sockaddr *sa, socklen_t sa_len,
                                          int timeout_ms, int *out_err) {
    pollfd_t pfd;
    int rc = 0;
    int err = 0;

    if (od_set_nonblocking(fd) != 0) {
        *out_err = od_socket_last_error();
        return -1;
    }

    if (connect(fd, sa, (int)sa_len) == 0) {
        *out_err = 0;
        return 0;
    }

    err = od_socket_last_error();
    if (!od_socket_error_is_inprogress(err)) {
        *out_err = err;
        return -1;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = OD_SOCK_POLLOUT;

    rc = od_socket_poll(&pfd, 1UL, timeout_ms);
    if (rc == 0) {
        *out_err = od_socket_timeout_error_code();
        return -1;
    }
    if (rc < 0) {
        *out_err = od_socket_last_error();
        return -1;
    }

    if (od_socket_get_so_error(fd, &err) != 0) {
        *out_err = od_socket_last_error();
        return -1;
    }
    if (err != 0) {
        *out_err = err;
        return -1;
    }

    *out_err = 0;
    return 0;
}

socket_t od_open_listener(const endpoint_t *listen_ep) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    char port[16];
    int yes = 1;
    socket_t sfd = OD_SOCK_INVALID;
    int gai_rc = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port, sizeof(port), "%u", (unsigned)listen_ep->port);
    gai_rc = getaddrinfo(listen_ep->host, port, &hints, &result);
    if (gai_rc != 0) {
        od_log_error("getaddrinfo(listen): %s", gai_strerror(gai_rc));
        return OD_SOCK_INVALID;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == OD_SOCK_INVALID) {
            continue;
        }

        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) != 0) {
            od_socket_close(sfd);
            sfd = OD_SOCK_INVALID;
            continue;
        }

        if (bind(sfd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
            break;
        }

        od_socket_close(sfd);
        sfd = OD_SOCK_INVALID;
    }

    freeaddrinfo(result);

    if (sfd == OD_SOCK_INVALID) {
        od_socket_log_error("bind");
        return OD_SOCK_INVALID;
    }

    if (listen(sfd, 64) != 0) {
        od_socket_log_error("listen");
        od_socket_close(sfd);
        return OD_SOCK_INVALID;
    }

    return sfd;
}

socket_t od_open_udp_socket(const endpoint_t *ep, bool do_bind) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    char port[16];
    int yes = 1;
    socket_t sfd = OD_SOCK_INVALID;
    int gai_rc = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (do_bind) {
        hints.ai_flags = AI_PASSIVE;
    }

    snprintf(port, sizeof(port), "%u", (unsigned)ep->port);
    gai_rc = getaddrinfo(ep->host, port, &hints, &result);
    if (gai_rc != 0) {
        od_log_error("getaddrinfo(udp): %s", gai_strerror(gai_rc));
        return OD_SOCK_INVALID;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == OD_SOCK_INVALID) {
            continue;
        }

        if (do_bind) {
            if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) != 0) {
                od_socket_close(sfd);
                sfd = OD_SOCK_INVALID;
                continue;
            }
            if (bind(sfd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
                break;
            }
            od_socket_close(sfd);
            sfd = OD_SOCK_INVALID;
        } else {
            if (connect(sfd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
                break;
            }
            od_socket_close(sfd);
            sfd = OD_SOCK_INVALID;
        }
    }

    freeaddrinfo(result);

    if (sfd == OD_SOCK_INVALID) {
        od_socket_log_error(do_bind ? "bind(udp)" : "connect(udp)");
    }
    return sfd;
}

socket_t od_connect_to_target_ex(const endpoint_t *target_ep, int timeout_ms,
                                 char *reason_buf, size_t reason_buf_sz) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    char port[16];
    char target_host[NI_MAXHOST];
    char target_port[NI_MAXSERV];
    char errbuf[256];
    socket_t cfd = OD_SOCK_INVALID;
    int connect_err = 0;
    int attempt = 0;
    int gai_rc = 0;

    if (reason_buf != NULL && reason_buf_sz > 0) {
        snprintf(reason_buf, reason_buf_sz, "unknown");
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port, sizeof(port), "%u", (unsigned)target_ep->port);
    gai_rc = getaddrinfo(target_ep->host, port, &hints, &result);
    if (gai_rc != 0) {
        od_log_error("getaddrinfo(target): %s", gai_strerror(gai_rc));
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "dns_error:%s", gai_strerror(gai_rc));
        }
        return OD_SOCK_INVALID;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        attempt++;
        od_addr_to_numeric(rp->ai_addr, (socklen_t)rp->ai_addrlen, target_host, sizeof(target_host),
                           target_port, sizeof(target_port));
        od_log_info("Connecting to target %s:%s (attempt=%d timeout=%dms)",
                    target_host, target_port, attempt, timeout_ms);

        cfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (cfd == OD_SOCK_INVALID) {
            od_socket_log_error("socket");
            continue;
        }

        if (od_socket_connect_with_timeout(cfd, rp->ai_addr, (socklen_t)rp->ai_addrlen, timeout_ms,
                                           &connect_err) == 0) {
            od_log_info("Connected to target %s:%s", target_host, target_port);
            break;
        }

        od_log_warn("Target connect failed %s:%s (%s)",
                    target_host, target_port,
                    od_socket_error_to_string(connect_err, errbuf, sizeof(errbuf)));
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "%s",
                     od_socket_error_to_string(connect_err, errbuf, sizeof(errbuf)));
        }

        od_socket_close(cfd);
        cfd = OD_SOCK_INVALID;
    }

    freeaddrinfo(result);

    if (cfd == OD_SOCK_INVALID) {
        od_log_warn("Could not connect to --to %s:%u after %d attempt(s)",
                    target_ep->host, (unsigned)target_ep->port, attempt);
        if (attempt == 0 && reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "no-address");
        }
    }
    return cfd;
}

socket_t od_connect_to_target(const endpoint_t *target_ep, int timeout_ms) {
    return od_connect_to_target_ex(target_ep, timeout_ms, NULL, 0);
}
