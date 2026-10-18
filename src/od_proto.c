#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od_log.h"
#include "od_proto.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

typedef struct {
    uint32_t magic_be;
    uint8_t version;
    uint8_t type;
    uint16_t flags_be;
    uint32_t stream_id_be;
    uint32_t length_be;
} od_wire_hdr_t;

int od_send_frame_io(const od_io_t *io, uint8_t type, uint16_t flags, uint32_t stream_id,
                     const void *payload, uint32_t length) {
    od_wire_hdr_t hdr;
    if (length > ODY_MAX_PAYLOAD) {
        od_log_error("frame too large: %lu", (unsigned long)length);
        return -1;
    }

    hdr.magic_be = htonl(ODY_MAGIC);
    hdr.version = ODY_VERSION;
    hdr.type = type;
    hdr.flags_be = htons(flags);
    hdr.stream_id_be = htonl(stream_id);
    hdr.length_be = htonl(length);

    if (io == NULL || io->write_all == NULL) {
        od_log_error("od_send_frame_io: invalid io");
        return -1;
    }

    if (io->write_all(io->ctx, (const uint8_t *)&hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (length > 0 && payload != NULL) {
        if (io->write_all(io->ctx, (const uint8_t *)payload, (size_t)length) != 0) {
            return -1;
        }
    }

    return 0;
}

int od_recv_frame_io(const od_io_t *io, od_frame_t *out, bool *out_closed) {
    od_wire_hdr_t wire;
    bool closed = false;
    uint32_t length = 0;

    memset(out, 0, sizeof(*out));
    *out_closed = false;

    if (io == NULL || io->read_all == NULL) {
        od_log_error("od_recv_frame_io: invalid io");
        return -1;
    }

    if (io->read_all(io->ctx, (uint8_t *)&wire, sizeof(wire), &closed) != 0) {
        return -1;
    }
    if (closed) {
        *out_closed = true;
        return 0;
    }

    out->hdr.magic = ntohl(wire.magic_be);
    out->hdr.version = wire.version;
    out->hdr.type = wire.type;
    out->hdr.flags = ntohs(wire.flags_be);
    out->hdr.stream_id = ntohl(wire.stream_id_be);
    out->hdr.length = ntohl(wire.length_be);

    if (out->hdr.magic != ODY_MAGIC || out->hdr.version != ODY_VERSION) {
        od_log_error("invalid frame header (magic/version)");
        return -1;
    }

    length = out->hdr.length;
    if (length > ODY_MAX_PAYLOAD) {
        od_log_error("payload too large: %lu", (unsigned long)length);
        return -1;
    }
    if (length == 0) {
        return 0;
    }

    out->payload = (uint8_t *)malloc(length);
    if (out->payload == NULL) {
        od_log_error("out of memory");
        return -1;
    }

    if (io->read_all(io->ctx, out->payload, length, &closed) != 0) {
        od_frame_free(out);
        return -1;
    }
    if (closed) {
        od_frame_free(out);
        *out_closed = true;
        return 0;
    }

    return 0;
}

int od_send_frame(socket_t fd, uint8_t type, uint16_t flags, uint32_t stream_id, const void *payload,
                  uint32_t length) {
    od_socket_io_ctx_t sctx;
    od_io_t io;
    od_io_init_socket(&io, &sctx, fd);
    return od_send_frame_io(&io, type, flags, stream_id, payload, length);
}

int od_recv_frame(socket_t fd, od_frame_t *out, bool *out_closed) {
    od_socket_io_ctx_t sctx;
    od_io_t io;
    od_io_init_socket(&io, &sctx, fd);
    return od_recv_frame_io(&io, out, out_closed);
}

void od_frame_free(od_frame_t *frame) {
    if (frame == NULL) {
        return;
    }
    free(frame->payload);
    memset(frame, 0, sizeof(*frame));
}

int od_proto_build_typed_response(char *out, size_t out_sz, bool ok, const char *code,
                                  const char *reason, const char *correlation_id,
                                  uint64_t ts_ms, const char *data) {
    int n = 0;
    size_t used = 0;
    if (out == NULL || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    n = snprintf(out, out_sz,
                 "ok=%s\ncode=%s\nreason=%s\ncorrelation_id=%s\nts_ms=%llu\n",
                 ok ? "true" : "false",
                 code != NULL ? code : "UNKNOWN",
                 reason != NULL ? reason : "",
                 correlation_id != NULL ? correlation_id : "0",
                 (unsigned long long)ts_ms);
    if (n <= 0 || (size_t)n >= out_sz) {
        return -1;
    }
    used = (size_t)n;
    if (data != NULL && data[0] != '\0') {
        n = snprintf(out + used, out_sz - used, "data:\n%s", data);
        if (n <= 0 || (size_t)n >= (out_sz - used)) {
            return -1;
        }
        used += (size_t)n;
    }
    return (int)used;
}

const char *od_msg_type_name(uint8_t type) {
    switch (type) {
        case OD_MSG_HELLO:
            return "HELLO";
        case OD_MSG_AUTH:
            return "AUTH";
        case OD_MSG_AUTH_OK:
            return "AUTH_OK";
        case OD_MSG_AUTH_FAIL:
            return "AUTH_FAIL";
        case OD_MSG_PING:
            return "PING";
        case OD_MSG_PONG:
            return "PONG";
        case OD_MSG_OPEN:
            return "OPEN";
        case OD_MSG_OPEN_OK:
            return "OPEN_OK";
        case OD_MSG_OPEN_FAIL:
            return "OPEN_FAIL";
        case OD_MSG_DATA:
            return "DATA";
        case OD_MSG_CLOSE:
            return "CLOSE";
        case OD_MSG_ERROR:
            return "ERROR";
        case OD_MSG_ADD_BIND:
            return "ADD_BIND";
        case OD_MSG_DEL_BIND:
            return "DEL_BIND";
        case OD_MSG_LIST_BIND:
            return "LIST_BIND";
        case OD_MSG_BIND_OK:
            return "BIND_OK";
        case OD_MSG_BIND_FAIL:
            return "BIND_FAIL";
        case OD_MSG_LIST_BIND_RESP:
            return "LIST_BIND_RESP";
        case OD_MSG_CAPS_REQ:
            return "CAPS_REQ";
        case OD_MSG_CAPS_RESP:
            return "CAPS_RESP";
        case OD_MSG_STATUS_REQ:
            return "STATUS_REQ";
        case OD_MSG_STATUS_RESP:
            return "STATUS_RESP";
        case OD_MSG_LIST_STREAM:
            return "LIST_STREAM";
        case OD_MSG_LIST_STREAM_RESP:
            return "LIST_STREAM_RESP";
        case OD_MSG_CLOSE_STREAM:
            return "CLOSE_STREAM";
        case OD_MSG_STREAM_OK:
            return "STREAM_OK";
        case OD_MSG_STREAM_FAIL:
            return "STREAM_FAIL";
        case OD_MSG_TUN_CAPS_REQ:
            return "TUN_CAPS_REQ";
        case OD_MSG_TUN_CAPS_RESP:
            return "TUN_CAPS_RESP";
        case OD_MSG_TUN_STATUS_REQ:
            return "TUN_STATUS_REQ";
        case OD_MSG_TUN_STATUS_RESP:
            return "TUN_STATUS_RESP";
        case OD_MSG_TUN_ROUTE_ADD:
            return "TUN_ROUTE_ADD";
        case OD_MSG_TUN_ROUTE_DEL:
            return "TUN_ROUTE_DEL";
        case OD_MSG_TUN_ROUTE_LIST:
            return "TUN_ROUTE_LIST";
        case OD_MSG_TUN_ROUTE_LIST_RESP:
            return "TUN_ROUTE_LIST_RESP";
        case OD_MSG_TUN_POLICY_SET:
            return "TUN_POLICY_SET";
        case OD_MSG_TUN_POLICY_GET:
            return "TUN_POLICY_GET";
        case OD_MSG_TUN_POLICY_RESP:
            return "TUN_POLICY_RESP";
        case OD_MSG_TUN_SESSION_LIST:
            return "TUN_SESSION_LIST";
        case OD_MSG_TUN_SESSION_LIST_RESP:
            return "TUN_SESSION_LIST_RESP";
        case OD_MSG_TUN_SESSION_CLOSE:
            return "TUN_SESSION_CLOSE";
        case OD_MSG_TUN_KILLSWITCH_SET:
            return "TUN_KILLSWITCH_SET";
        case OD_MSG_TUN_MTU_SET:
            return "TUN_MTU_SET";
        case OD_MSG_TUN_PKT:
            return "TUN_PKT";
        case OD_MSG_TUN_OK:
            return "TUN_OK";
        case OD_MSG_TUN_FAIL:
            return "TUN_FAIL";
        case OD_MSG_SNAPSHOT_REQ:
            return "SNAPSHOT_REQ";
        case OD_MSG_SNAPSHOT_RESP:
            return "SNAPSHOT_RESP";
        default:
            return "UNKNOWN";
    }
}
