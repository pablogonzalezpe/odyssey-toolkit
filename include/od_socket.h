#ifndef OD_SOCKET_H
#define OD_SOCKET_H

#include <stdbool.h>
#include <stddef.h>

#include "od_types.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET socket_t;
typedef WSAPOLLFD pollfd_t;
#define OD_SOCK_INVALID INVALID_SOCKET
#define OD_SOCK_POLLIN POLLRDNORM
#define OD_SOCK_POLLOUT POLLWRNORM
#define OD_SOCK_SHUT_WR SD_SEND
#else
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
typedef int socket_t;
typedef struct pollfd pollfd_t;
#define OD_SOCK_INVALID (-1)
#define OD_SOCK_POLLIN POLLIN
#define OD_SOCK_POLLOUT POLLOUT
#define OD_SOCK_SHUT_WR SHUT_WR
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef NI_MAXSERV
#define NI_MAXSERV 32
#endif

int od_socket_init(void);
void od_socket_cleanup(void);
int od_socket_last_error(void);
bool od_socket_error_is_retryable(int err);
bool od_socket_error_is_notconn(int err);
void od_socket_log_error(const char *ctx);
int od_socket_close(socket_t fd);
int od_socket_poll(pollfd_t *fds, unsigned long count, int timeout_ms);
int od_set_nonblocking(socket_t fd);
socket_t od_accept_with_peer(socket_t lfd, char *peer_host, size_t peer_host_sz, uint16_t *peer_port);

socket_t od_open_listener(const endpoint_t *listen_ep);
socket_t od_open_udp_socket(const endpoint_t *ep, bool do_bind);
socket_t od_connect_to_target(const endpoint_t *target_ep, int timeout_ms);
socket_t od_connect_to_target_ex(const endpoint_t *target_ep, int timeout_ms,
                                 char *reason_buf, size_t reason_buf_sz);

#endif
