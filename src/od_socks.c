#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "od_socks.h"
#include "od_socket.h"

static int socks_recv_all(socket_t fd, uint8_t *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        int n = recv(fd, (char *)(buf + off), (int)(len - off), 0);
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

static int socks_send_all(socket_t fd, const uint8_t *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        int n = send(fd, (const char *)(buf + off), (int)(len - off), 0);
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

static bool method_offered(const uint8_t *methods, size_t nmethods, uint8_t method) {
    size_t i = 0;
    for (i = 0; i < nmethods; i++) {
        if (methods[i] == method) {
            return true;
        }
    }
    return false;
}

static int socks_auth_userpass(socket_t fd, const char *username, const char *password) {
    uint8_t hdr[2];
    uint8_t ulen = 0;
    uint8_t plen = 0;
    char user_buf[256];
    char pass_buf[256];
    uint8_t resp[2];
    size_t expected_ulen = 0;
    size_t expected_plen = 0;
    bool ok = false;

    if (username == NULL || password == NULL) {
        return -1;
    }

    if (socks_recv_all(fd, hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (hdr[0] != 0x01u) {
        return -1;
    }

    ulen = hdr[1];
    if (ulen == 0u) {
        return -1;
    }
    if (socks_recv_all(fd, (uint8_t *)user_buf, (size_t)ulen) != 0) {
        return -1;
    }
    user_buf[ulen] = '\0';

    if (socks_recv_all(fd, &plen, 1) != 0) {
        return -1;
    }
    if (plen == 0u) {
        return -1;
    }
    if (socks_recv_all(fd, (uint8_t *)pass_buf, (size_t)plen) != 0) {
        return -1;
    }
    pass_buf[plen] = '\0';

    expected_ulen = strlen(username);
    expected_plen = strlen(password);
    ok = ((size_t)ulen == expected_ulen && (size_t)plen == expected_plen &&
          memcmp(user_buf, username, expected_ulen) == 0 &&
          memcmp(pass_buf, password, expected_plen) == 0);

    resp[0] = 0x01u;
    resp[1] = ok ? 0x00u : 0x01u;
    if (socks_send_all(fd, resp, sizeof(resp)) != 0) {
        return -1;
    }

    return ok ? 0 : -1;
}

int od_socks_negotiate(socket_t fd, const char *username, const char *password) {
    uint8_t hdr[2];
    uint8_t methods[255];
    uint8_t sel[2];
    uint8_t nmethods = 0;
    bool require_userpass = false;
    uint8_t wanted_method = OD_SOCKS_METHOD_NOAUTH;
    bool offered = false;

    if (socks_recv_all(fd, hdr, sizeof(hdr)) != 0) {
        return -1;
    }

    if (hdr[0] != OD_SOCKS_VERSION) {
        return -1;
    }

    nmethods = hdr[1];
    if (nmethods == 0) {
        return -1;
    }

    if (socks_recv_all(fd, methods, (size_t)nmethods) != 0) {
        return -1;
    }

    require_userpass = (username != NULL && password != NULL);
    wanted_method = require_userpass ? OD_SOCKS_METHOD_USERPASS : OD_SOCKS_METHOD_NOAUTH;
    offered = method_offered(methods, (size_t)nmethods, wanted_method);

    sel[0] = OD_SOCKS_VERSION;
    sel[1] = offered ? wanted_method : OD_SOCKS_METHOD_NO_ACCEPTABLE;
    if (socks_send_all(fd, sel, sizeof(sel)) != 0) {
        return -1;
    }

    if (!offered) {
        return -1;
    }

    if (wanted_method == OD_SOCKS_METHOD_USERPASS) {
        return socks_auth_userpass(fd, username, password);
    }
    return 0;
}

int od_socks_read_connect(socket_t fd, endpoint_t *out_target, uint8_t *out_rep_code) {
    uint8_t req[4];
    uint8_t port_raw[2];
    uint16_t port = 0;

    if (out_target == NULL || out_rep_code == NULL) {
        return -1;
    }

    memset(out_target, 0, sizeof(*out_target));
    *out_rep_code = OD_SOCKS_REP_GENERAL_FAILURE;

    if (socks_recv_all(fd, req, sizeof(req)) != 0) {
        return -1;
    }

    if (req[0] != OD_SOCKS_VERSION) {
        return -1;
    }
    if (req[1] != OD_SOCKS_CMD_CONNECT) {
        *out_rep_code = OD_SOCKS_REP_COMMAND_NOT_SUPPORTED;
        return -1;
    }
    if (req[2] != 0x00u) {
        return -1;
    }

    if (req[3] == OD_SOCKS_ATYP_IPV4) {
        uint8_t ipv4[4];
        int n = 0;

        if (socks_recv_all(fd, ipv4, sizeof(ipv4)) != 0) {
            return -1;
        }

        n = snprintf(out_target->host, sizeof(out_target->host), "%u.%u.%u.%u",
                     (unsigned)ipv4[0], (unsigned)ipv4[1], (unsigned)ipv4[2], (unsigned)ipv4[3]);
        if (n <= 0 || (size_t)n >= sizeof(out_target->host)) {
            return -1;
        }
    } else if (req[3] == OD_SOCKS_ATYP_DOMAIN) {
        uint8_t dlen = 0;
        if (socks_recv_all(fd, &dlen, 1) != 0) {
            return -1;
        }
        if (dlen == 0) {
            return -1;
        }
        if (socks_recv_all(fd, (uint8_t *)out_target->host, (size_t)dlen) != 0) {
            return -1;
        }
        out_target->host[dlen] = '\0';
    } else {
        *out_rep_code = OD_SOCKS_REP_ATYP_NOT_SUPPORTED;
        return -1;
    }

    if (socks_recv_all(fd, port_raw, sizeof(port_raw)) != 0) {
        return -1;
    }
    port = (uint16_t)(((uint16_t)port_raw[0] << 8) | (uint16_t)port_raw[1]);
    if (port == 0) {
        return -1;
    }
    out_target->port = port;
    *out_rep_code = OD_SOCKS_REP_SUCCEEDED;
    return 0;
}

int od_socks_send_reply(socket_t fd, uint8_t rep_code) {
    uint8_t resp[10];

    memset(resp, 0, sizeof(resp));
    resp[0] = OD_SOCKS_VERSION;
    resp[1] = rep_code;
    resp[2] = 0x00u;
    resp[3] = OD_SOCKS_ATYP_IPV4;
    /* BND.ADDR/BND.PORT left as 0.0.0.0:0 */

    return socks_send_all(fd, resp, sizeof(resp));
}
