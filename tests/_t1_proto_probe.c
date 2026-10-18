#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "od_proto.h"

static int run_names(void) {
    uint8_t ids[] = {
        OD_MSG_TUN_CAPS_REQ,
        OD_MSG_TUN_CAPS_RESP,
        OD_MSG_TUN_STATUS_REQ,
        OD_MSG_TUN_STATUS_RESP,
        OD_MSG_TUN_ROUTE_ADD,
        OD_MSG_TUN_ROUTE_DEL,
        OD_MSG_TUN_ROUTE_LIST,
        OD_MSG_TUN_ROUTE_LIST_RESP,
        OD_MSG_TUN_POLICY_SET,
        OD_MSG_TUN_POLICY_GET,
        OD_MSG_TUN_POLICY_RESP,
        OD_MSG_TUN_SESSION_LIST,
        OD_MSG_TUN_SESSION_LIST_RESP,
        OD_MSG_TUN_SESSION_CLOSE,
        OD_MSG_TUN_KILLSWITCH_SET,
        OD_MSG_TUN_MTU_SET,
        OD_MSG_TUN_PKT,
        OD_MSG_TUN_OK,
        OD_MSG_TUN_FAIL,
        OD_MSG_SNAPSHOT_REQ,
        OD_MSG_SNAPSHOT_RESP
    };
    size_t i = 0;
    for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        printf("%u=%s\n", (unsigned)ids[i], od_msg_type_name(ids[i]));
    }
    return 0;
}

static int run_typed(void) {
    char buf[1024];
    if (od_proto_build_typed_response(buf, sizeof(buf), true, "OK", "probe", "corr-42", 123456789ULL,
                                      "k1=v1\nk2=v2\n") < 0) {
        return 1;
    }
    fputs(buf, stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s names|typed\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "names") == 0) {
        return run_names();
    }
    if (strcmp(argv[1], "typed") == 0) {
        return run_typed();
    }
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 1;
}
