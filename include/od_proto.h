#ifndef OD_PROTO_H
#define OD_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "od_io.h"
#include "od_socket.h"

#define ODY_MAGIC 0x4F445931u
#define ODY_VERSION 1u
#define ODY_MAX_PAYLOAD (64u * 1024u)

enum od_msg_type {
    OD_MSG_HELLO = 1,
    OD_MSG_AUTH = 2,
    OD_MSG_AUTH_OK = 3,
    OD_MSG_AUTH_FAIL = 4,
    OD_MSG_PING = 5,
    OD_MSG_PONG = 6,
    OD_MSG_OPEN = 7,
    OD_MSG_OPEN_OK = 8,
    OD_MSG_OPEN_FAIL = 9,
    OD_MSG_DATA = 10,
    OD_MSG_CLOSE = 11,
    OD_MSG_ERROR = 12,
    OD_MSG_ADD_BIND = 13,
    OD_MSG_DEL_BIND = 14,
    OD_MSG_LIST_BIND = 15,
    OD_MSG_BIND_OK = 16,
    OD_MSG_BIND_FAIL = 17,
    OD_MSG_LIST_BIND_RESP = 18,
    OD_MSG_CAPS_REQ = 19,
    OD_MSG_CAPS_RESP = 20,
    OD_MSG_STATUS_REQ = 21,
    OD_MSG_STATUS_RESP = 22,
    OD_MSG_LIST_STREAM = 23,
    OD_MSG_LIST_STREAM_RESP = 24,
    OD_MSG_CLOSE_STREAM = 25,
    OD_MSG_STREAM_OK = 26,
    OD_MSG_STREAM_FAIL = 27,
    OD_MSG_TUN_CAPS_REQ = 28,
    OD_MSG_TUN_CAPS_RESP = 29,
    OD_MSG_TUN_STATUS_REQ = 30,
    OD_MSG_TUN_STATUS_RESP = 31,
    OD_MSG_TUN_ROUTE_ADD = 32,
    OD_MSG_TUN_ROUTE_DEL = 33,
    OD_MSG_TUN_ROUTE_LIST = 34,
    OD_MSG_TUN_ROUTE_LIST_RESP = 35,
    OD_MSG_TUN_POLICY_SET = 36,
    OD_MSG_TUN_POLICY_GET = 37,
    OD_MSG_TUN_POLICY_RESP = 38,
    OD_MSG_TUN_SESSION_LIST = 39,
    OD_MSG_TUN_SESSION_LIST_RESP = 40,
    OD_MSG_TUN_SESSION_CLOSE = 41,
    OD_MSG_TUN_KILLSWITCH_SET = 42,
    OD_MSG_TUN_MTU_SET = 43,
    OD_MSG_TUN_PKT = 44,
    OD_MSG_TUN_OK = 45,
    OD_MSG_TUN_FAIL = 46,
    OD_MSG_SNAPSHOT_REQ = 47,
    OD_MSG_SNAPSHOT_RESP = 48
};

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} od_frame_hdr_t;

typedef struct {
    od_frame_hdr_t hdr;
    uint8_t *payload;
} od_frame_t;

int od_send_frame(socket_t fd, uint8_t type, uint16_t flags, uint32_t stream_id, const void *payload,
                  uint32_t length);
int od_recv_frame(socket_t fd, od_frame_t *out, bool *out_closed);
int od_send_frame_io(const od_io_t *io, uint8_t type, uint16_t flags, uint32_t stream_id,
                     const void *payload, uint32_t length);
int od_recv_frame_io(const od_io_t *io, od_frame_t *out, bool *out_closed);
void od_frame_free(od_frame_t *frame);
const char *od_msg_type_name(uint8_t type);
int od_proto_build_typed_response(char *out, size_t out_sz, bool ok, const char *code,
                                  const char *reason, const char *correlation_id,
                                  uint64_t ts_ms, const char *data);

#endif
