#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od_proto.h"
#include "od_socket.h"

static int recv_expected(socket_t fd, uint8_t expected, od_frame_t *out) {
    int tries = 0;
    for (tries = 0; tries < 16; tries++) {
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
        if (frame.hdr.type == OD_MSG_TUN_POLICY_GET ||
            frame.hdr.type == OD_MSG_TUN_KILLSWITCH_SET) {
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

static int do_handshake(socket_t fd, const char *token) {
    od_frame_t frame;
    bool closed = false;
    memset(&frame, 0, sizeof(frame));
    if (od_send_frame(fd, OD_MSG_HELLO, 0, 0, "odyssey/1", 8) != 0) {
        return -1;
    }
    if (recv_expected(fd, OD_MSG_HELLO, &frame) != 0) {
        return -1;
    }
    od_frame_free(&frame);
    if (od_send_frame(fd, OD_MSG_AUTH, 0, 0, token, (uint32_t)strlen(token)) != 0) {
        return -1;
    }
    if (od_recv_frame(fd, &frame, &closed) != 0) {
        return -1;
    }
    if (closed) {
        return -1;
    }
    if (frame.hdr.type == OD_MSG_AUTH_FAIL) {
        od_frame_free(&frame);
        return -1;
    }
    if (frame.hdr.type != OD_MSG_AUTH_OK) {
        od_frame_free(&frame);
        return -1;
    }
    od_frame_free(&frame);
    return 0;
}

int main(int argc, char **argv) {
    endpoint_t ep;
    socket_t fd = OD_SOCK_INVALID;
    uint8_t req = 0;
    uint8_t resp_ok = 0;
    uint32_t timeout_ms = 3000;
    const char *payload = NULL;
    od_frame_t frame;

    if (argc < 5) {
        fprintf(stderr, "usage: %s HOST PORT TOKEN caps|status|route-list|route-add|policy-show|snapshot\n", argv[0]);
        return 1;
    }
    memset(&ep, 0, sizeof(ep));
    memset(&frame, 0, sizeof(frame));
    snprintf(ep.host, sizeof(ep.host), "%s", argv[1]);
    ep.port = (uint16_t)strtoul(argv[2], NULL, 10);
    if (ep.port == 0) {
        fprintf(stderr, "invalid port\n");
        return 1;
    }
    if (strcmp(argv[4], "caps") == 0) {
        req = OD_MSG_TUN_CAPS_REQ;
        resp_ok = OD_MSG_TUN_CAPS_RESP;
    } else if (strcmp(argv[4], "status") == 0) {
        req = OD_MSG_TUN_STATUS_REQ;
        resp_ok = OD_MSG_TUN_STATUS_RESP;
    } else if (strcmp(argv[4], "route-list") == 0) {
        req = OD_MSG_TUN_ROUTE_LIST;
        resp_ok = OD_MSG_TUN_ROUTE_LIST_RESP;
    } else if (strcmp(argv[4], "route-add") == 0) {
        req = OD_MSG_TUN_ROUTE_ADD;
        resp_ok = OD_MSG_TUN_OK;
        payload = "10.10.10.0/24";
    } else if (strcmp(argv[4], "policy-show") == 0) {
        req = OD_MSG_TUN_POLICY_GET;
        resp_ok = OD_MSG_TUN_POLICY_RESP;
    } else if (strcmp(argv[4], "snapshot") == 0) {
        req = OD_MSG_SNAPSHOT_REQ;
        resp_ok = OD_MSG_SNAPSHOT_RESP;
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[4]);
        return 1;
    }

    if (od_socket_init() != 0) {
        return 1;
    }
    fd = od_connect_to_target(&ep, (int)timeout_ms);
    if (fd == OD_SOCK_INVALID) {
        od_socket_cleanup();
        return 1;
    }
    if (do_handshake(fd, argv[3]) != 0) {
        od_socket_close(fd);
        od_socket_cleanup();
        return 1;
    }
    if (payload != NULL) {
        if (od_send_frame(fd, req, 0, 0, payload, (uint32_t)strlen(payload)) != 0) {
            od_socket_close(fd);
            od_socket_cleanup();
            return 1;
        }
    } else {
        if (od_send_frame(fd, req, 0, 0, NULL, 0) != 0) {
            od_socket_close(fd);
            od_socket_cleanup();
            return 1;
        }
    }
    if (recv_expected(fd, resp_ok, &frame) != 0) {
        od_socket_close(fd);
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
    od_socket_close(fd);
    od_socket_cleanup();
    return 0;
}
