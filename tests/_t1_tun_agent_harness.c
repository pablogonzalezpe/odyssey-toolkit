#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "od_proto.h"
#include "od_socket.h"

static int recv_expected(socket_t fd, uint8_t expected, od_frame_t *out) {
    int tries = 0;
    for (tries = 0; tries < 32; tries++) {
        bool closed = false;
        od_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        if (od_recv_frame(fd, &frame, &closed) != 0) {
            return -1;
        }
        if (closed) {
            return -1;
        }
        if (frame.hdr.type == OD_MSG_PING) {
            (void)od_send_frame(fd, OD_MSG_PONG, 0, 0, NULL, 0);
            od_frame_free(&frame);
            continue;
        }
        if (frame.hdr.type != expected) {
            fprintf(stderr, "unexpected frame type: %s (expected %s)\n",
                    od_msg_type_name(frame.hdr.type), od_msg_type_name(expected));
            od_frame_free(&frame);
            return -1;
        }
        *out = frame;
        return 0;
    }
    return -1;
}

static int do_server_handshake(socket_t fd, const char *token) {
    od_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    if (recv_expected(fd, OD_MSG_HELLO, &frame) != 0) {
        return -1;
    }
    od_frame_free(&frame);
    if (od_send_frame(fd, OD_MSG_HELLO, 0, 0, "odyssey/1", 8) != 0) {
        return -1;
    }
    if (recv_expected(fd, OD_MSG_AUTH, &frame) != 0) {
        return -1;
    }
    if (frame.hdr.length != strlen(token) || memcmp(frame.payload, token, frame.hdr.length) != 0) {
        const char *msg = "invalid token";
        (void)od_send_frame(fd, OD_MSG_AUTH_FAIL, 0, 0, msg, (uint32_t)strlen(msg));
        od_frame_free(&frame);
        return -1;
    }
    od_frame_free(&frame);
    if (od_send_frame(fd, OD_MSG_AUTH_OK, 0, 0, NULL, 0) != 0) {
        return -1;
    }
    return 0;
}

static int build_ipv4_tcp_packet(const char *dst_ip, uint16_t dst_port,
                                 uint8_t *out, uint32_t *out_len) {
    struct in_addr src;
    struct in_addr dst;
    if (out == NULL || out_len == NULL || dst_ip == NULL) {
        return -1;
    }
    if (inet_pton(AF_INET, "10.1.1.10", &src) != 1) {
        return -1;
    }
    if (inet_pton(AF_INET, dst_ip, &dst) != 1) {
        return -1;
    }
    memset(out, 0, 40);
    out[0] = 0x45;
    out[2] = 0x00;
    out[3] = 0x28;
    out[8] = 64;
    out[9] = 6;
    memcpy(out + 12, &src.s_addr, 4);
    memcpy(out + 16, &dst.s_addr, 4);
    out[20] = 0x30;
    out[21] = 0x39;
    out[22] = (uint8_t)(dst_port >> 8);
    out[23] = (uint8_t)(dst_port & 0xFF);
    out[32] = 0x50;
    out[33] = 0x02;
    *out_len = 40;
    return 0;
}

static int send_noop(socket_t fd, uint8_t type, const char *payload) {
    uint32_t payload_len = payload != NULL ? (uint32_t)strlen(payload) : 0;
    return od_send_frame(fd, type, 0, 0, payload, payload_len);
}

static int recv_and_print(socket_t fd, uint8_t expected) {
    od_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    if (recv_expected(fd, expected, &frame) != 0) {
        return -1;
    }
    if (expected == OD_MSG_TUN_PKT) {
        printf("pkt-len=%u\n", (unsigned)frame.hdr.length);
    } else if (frame.hdr.length > 0 && frame.payload != NULL) {
        fwrite(frame.payload, 1, frame.hdr.length, stdout);
        if (frame.payload[frame.hdr.length - 1] != '\n') {
            fputc('\n', stdout);
        }
    }
    od_frame_free(&frame);
    return 0;
}

int main(int argc, char **argv) {
    endpoint_t ep;
    socket_t lfd = OD_SOCK_INVALID;
    socket_t cfd = OD_SOCK_INVALID;
    char peer_host[NI_MAXHOST];
    uint16_t peer_port = 0;
    uint8_t req = 0;
    uint8_t expect = 0;
    const char *payload = NULL;
    uint8_t payload_raw[128];
    uint32_t payload_len = 0;
    bool pkt_then_status = false;
    od_frame_t frame;

    if (argc < 4) {
        fprintf(stderr,
                "usage: %s PORT TOKEN caps|status|route-list|route-add|policy-show|"
                "policy-add-port-allow|policy-del-port-deny|policy-add-cidr-allow|"
                "policy-del-cidr-deny|killswitch-on-status-deny|pkt-allow|pkt-deny-port|"
                "pkt-deny-cidr|pkt-allow-status\n",
                argv[0]);
        return 1;
    }
    memset(&ep, 0, sizeof(ep));
    memset(peer_host, 0, sizeof(peer_host));
    memset(&frame, 0, sizeof(frame));
    pkt_then_status = false;

    snprintf(ep.host, sizeof(ep.host), "127.0.0.1");
    ep.port = (uint16_t)strtoul(argv[1], NULL, 10);
    if (ep.port == 0) {
        fprintf(stderr, "invalid listen port\n");
        return 1;
    }

    memset(payload_raw, 0, sizeof(payload_raw));

    if (strcmp(argv[3], "caps") == 0) {
        req = OD_MSG_TUN_CAPS_REQ;
        expect = OD_MSG_TUN_CAPS_RESP;
    } else if (strcmp(argv[3], "status") == 0) {
        req = OD_MSG_TUN_STATUS_REQ;
        expect = OD_MSG_TUN_STATUS_RESP;
    } else if (strcmp(argv[3], "route-list") == 0) {
        req = OD_MSG_TUN_ROUTE_LIST;
        expect = OD_MSG_TUN_ROUTE_LIST_RESP;
    } else if (strcmp(argv[3], "route-add") == 0) {
        req = OD_MSG_TUN_ROUTE_ADD;
        expect = OD_MSG_TUN_FAIL;
        payload = "10.123.0.0/24";
    } else if (strcmp(argv[3], "policy-show") == 0) {
        req = OD_MSG_TUN_POLICY_GET;
        expect = OD_MSG_TUN_POLICY_RESP;
    } else if (strcmp(argv[3], "policy-add-port-allow") == 0 ||
               strcmp(argv[3], "policy-del-port-deny") == 0 ||
               strcmp(argv[3], "policy-add-cidr-allow") == 0 ||
               strcmp(argv[3], "policy-del-cidr-deny") == 0 ||
               strcmp(argv[3], "killswitch-on-status-deny") == 0) {
        req = 0;
        expect = 0;
    } else if (strcmp(argv[3], "pkt-allow") == 0) {
        req = OD_MSG_TUN_PKT;
        expect = OD_MSG_TUN_PKT;
        if (build_ipv4_tcp_packet("10.230.0.25", 443, payload_raw, &payload_len) != 0) {
            fprintf(stderr, "failed to build allow packet\n");
            return 1;
        }
    } else if (strcmp(argv[3], "pkt-deny-port") == 0) {
        req = OD_MSG_TUN_PKT;
        expect = OD_MSG_TUN_FAIL;
        if (build_ipv4_tcp_packet("10.230.0.25", 444, payload_raw, &payload_len) != 0) {
            fprintf(stderr, "failed to build deny-port packet\n");
            return 1;
        }
    } else if (strcmp(argv[3], "pkt-deny-cidr") == 0) {
        req = OD_MSG_TUN_PKT;
        expect = OD_MSG_TUN_FAIL;
        if (build_ipv4_tcp_packet("10.231.0.25", 443, payload_raw, &payload_len) != 0) {
            fprintf(stderr, "failed to build deny-cidr packet\n");
            return 1;
        }
    } else if (strcmp(argv[3], "pkt-allow-status") == 0) {
        req = OD_MSG_TUN_PKT;
        expect = OD_MSG_TUN_PKT;
        pkt_then_status = true;
        if (build_ipv4_tcp_packet("10.230.0.25", 443, payload_raw, &payload_len) != 0) {
            fprintf(stderr, "failed to build allow-status packet\n");
            return 1;
        }
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[3]);
        return 1;
    }

    if (od_socket_init() != 0) {
        return 1;
    }
    lfd = od_open_listener(&ep);
    if (lfd == OD_SOCK_INVALID) {
        od_socket_cleanup();
        return 1;
    }
    cfd = od_accept_with_peer(lfd, peer_host, sizeof(peer_host), &peer_port);
    if (cfd == OD_SOCK_INVALID) {
        od_socket_close(lfd);
        od_socket_cleanup();
        return 1;
    }

    if (do_server_handshake(cfd, argv[2]) != 0) {
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 1;
    }
    if (strcmp(argv[3], "policy-add-port-allow") == 0) {
        if (send_noop(cfd, OD_MSG_TUN_POLICY_SET, "ALLOW_PORT_ADD\ttcp:444") != 0 ||
            send_noop(cfd, OD_MSG_TUN_POLICY_GET, NULL) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_POLICY_RESP) != 0 ||
            build_ipv4_tcp_packet("10.230.0.25", 444, payload_raw, &payload_len) != 0 ||
            od_send_frame(cfd, OD_MSG_TUN_PKT, 0, 0, payload_raw, payload_len) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_PKT) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 0;
    }
    if (strcmp(argv[3], "policy-del-port-deny") == 0) {
        if (send_noop(cfd, OD_MSG_TUN_POLICY_SET, "ALLOW_PORT_DEL\ttcp:443") != 0 ||
            send_noop(cfd, OD_MSG_TUN_POLICY_GET, NULL) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_POLICY_RESP) != 0 ||
            build_ipv4_tcp_packet("10.230.0.25", 443, payload_raw, &payload_len) != 0 ||
            od_send_frame(cfd, OD_MSG_TUN_PKT, 0, 0, payload_raw, payload_len) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_FAIL) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 0;
    }
    if (strcmp(argv[3], "policy-add-cidr-allow") == 0) {
        if (send_noop(cfd, OD_MSG_TUN_POLICY_SET, "ALLOW_CIDR_ADD\t10.231.0.0/24") != 0 ||
            send_noop(cfd, OD_MSG_TUN_POLICY_GET, NULL) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_POLICY_RESP) != 0 ||
            build_ipv4_tcp_packet("10.231.0.25", 443, payload_raw, &payload_len) != 0 ||
            od_send_frame(cfd, OD_MSG_TUN_PKT, 0, 0, payload_raw, payload_len) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_PKT) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 0;
    }
    if (strcmp(argv[3], "policy-del-cidr-deny") == 0) {
        if (send_noop(cfd, OD_MSG_TUN_POLICY_SET, "ALLOW_CIDR_DEL\t10.230.0.0/24") != 0 ||
            send_noop(cfd, OD_MSG_TUN_POLICY_GET, NULL) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_POLICY_RESP) != 0 ||
            build_ipv4_tcp_packet("10.230.0.25", 443, payload_raw, &payload_len) != 0 ||
            od_send_frame(cfd, OD_MSG_TUN_PKT, 0, 0, payload_raw, payload_len) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_FAIL) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 0;
    }
    if (strcmp(argv[3], "killswitch-on-status-deny") == 0) {
        if (send_noop(cfd, OD_MSG_TUN_KILLSWITCH_SET, "enabled") != 0 ||
            send_noop(cfd, OD_MSG_TUN_STATUS_REQ, NULL) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_STATUS_RESP) != 0 ||
            build_ipv4_tcp_packet("10.230.0.25", 443, payload_raw, &payload_len) != 0 ||
            od_send_frame(cfd, OD_MSG_TUN_PKT, 0, 0, payload_raw, payload_len) != 0 ||
            recv_and_print(cfd, OD_MSG_TUN_FAIL) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 0;
    }
    if (payload_len > 0) {
        if (od_send_frame(cfd, req, 0, 0, payload_raw, payload_len) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
    } else if (payload != NULL) {
        if (od_send_frame(cfd, req, 0, 0, payload, (uint32_t)strlen(payload)) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
    } else {
        if (od_send_frame(cfd, req, 0, 0, NULL, 0) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
    }
    if (recv_expected(cfd, expect, &frame) != 0) {
        od_socket_close(cfd);
        od_socket_close(lfd);
        od_socket_cleanup();
        return 1;
    }
    if (expect == OD_MSG_TUN_PKT) {
        printf("pkt-len=%u\n", (unsigned)frame.hdr.length);
    } else if (frame.hdr.length > 0 && frame.payload != NULL) {
        fwrite(frame.payload, 1, frame.hdr.length, stdout);
        if (frame.payload[frame.hdr.length - 1] != '\n') {
            fputc('\n', stdout);
        }
    }
    od_frame_free(&frame);
    if (pkt_then_status) {
        if (od_send_frame(cfd, OD_MSG_TUN_STATUS_REQ, 0, 0, NULL, 0) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        if (recv_expected(cfd, OD_MSG_TUN_STATUS_RESP, &frame) != 0) {
            od_socket_close(cfd);
            od_socket_close(lfd);
            od_socket_cleanup();
            return 1;
        }
        if (frame.hdr.length > 0 && frame.payload != NULL) {
            fwrite(frame.payload, 1, frame.hdr.length, stdout);
            if (frame.payload[frame.hdr.length - 1] != '\n') {
                fputc('\n', stdout);
            }
        }
        od_frame_free(&frame);
    }
    od_socket_close(cfd);
    od_socket_close(lfd);
    od_socket_cleanup();
    return 0;
}
