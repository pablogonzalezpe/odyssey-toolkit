#include "od_tun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od_hardening.h"
#include "od_tun_dev.h"

static void tun_set_error(od_tun_error_t *err, od_tun_error_code_t code, const char *msg) {
    if (err == NULL) {
        return;
    }
    err->code = code;
    if (msg == NULL || msg[0] == '\0') {
        err->message[0] = '\0';
        return;
    }
    snprintf(err->message, sizeof(err->message), "%s", msg);
}

static int tun_validate_cidr_strict(const char *raw, bool reject_default_route, od_tun_error_t *err,
                                    od_tun_error_code_t invalid_code) {
    if (raw == NULL || raw[0] == '\0' || strchr(raw, '/') == NULL ||
        od_hardening_validate_source_spec(raw) != 0) {
        tun_set_error(err, invalid_code, "invalid CIDR");
        return -1;
    }
    if (reject_default_route && strcmp(raw, "0.0.0.0/0") == 0) {
        tun_set_error(err, OD_TUN_ERR_DEFAULT_ROUTE_NOT_ALLOWED,
                      "default route 0.0.0.0/0 not allowed in T1");
        return -1;
    }
    return 0;
}

static int tun_validate_port_spec(const char *raw) {
    char copy[64];
    char *sep = NULL;
    const char *proto = NULL;
    char *endptr = NULL;
    unsigned long port = 0;

    if (raw == NULL || raw[0] == '\0' || strlen(raw) >= sizeof(copy)) {
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", raw);
    sep = strchr(copy, ':');
    if (sep == NULL || sep == copy || *(sep + 1) == '\0') {
        return -1;
    }
    *sep = '\0';
    proto = copy;
    if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
        return -1;
    }
    port = strtoul(sep + 1, &endptr, 10);
    if (endptr == sep + 1 || *endptr != '\0' || port == 0UL || port > 65535UL) {
        return -1;
    }
    return 0;
}

int od_tun_validate_gateway_opts(const od_tun_gateway_opts_t *opts, od_tun_error_t *err) {
    size_t i = 0;
    if (err != NULL) {
        memset(err, 0, sizeof(*err));
    }
    if (opts == NULL) {
        tun_set_error(err, OD_TUN_ERR_INVALID_ARG, "gateway options are null");
        return -1;
    }
    if (opts->tun_name == NULL || opts->tun_name[0] == '\0') {
        tun_set_error(err, OD_TUN_ERR_TUN_NAME_REQUIRED, "tun-name is required");
        return -1;
    }
    if (opts->tun_cidr == NULL || opts->tun_cidr[0] == '\0') {
        tun_set_error(err, OD_TUN_ERR_TUN_CIDR_REQUIRED, "tun-cidr is required");
        return -1;
    }
    if (tun_validate_cidr_strict(opts->tun_cidr, true, err, OD_TUN_ERR_TUN_CIDR_INVALID) != 0) {
        if (err != NULL && err->code == OD_TUN_ERR_TUN_CIDR_INVALID) {
            tun_set_error(err, OD_TUN_ERR_TUN_CIDR_INVALID, "invalid tun-cidr");
        }
        return -1;
    }
    if (opts->gateway_mtu < OD_TUN_MTU_MIN || opts->gateway_mtu > OD_TUN_MTU_MAX) {
        tun_set_error(err, OD_TUN_ERR_GATEWAY_MTU_INVALID, "invalid gateway-mtu");
        return -1;
    }
    if (opts->route_allow == NULL || opts->route_allow_count == 0) {
        tun_set_error(err, OD_TUN_ERR_ROUTE_ALLOW_REQUIRED, "route-allow list is required");
        return -1;
    }
    for (i = 0; i < opts->route_allow_count; i++) {
        if (tun_validate_cidr_strict(opts->route_allow[i], true, err, OD_TUN_ERR_ROUTE_ALLOW_INVALID) != 0) {
            if (err != NULL && err->code == OD_TUN_ERR_ROUTE_ALLOW_INVALID) {
                tun_set_error(err, OD_TUN_ERR_ROUTE_ALLOW_INVALID, "invalid route-allow CIDR");
            }
            return -1;
        }
    }
    return 0;
}

int od_tun_validate_agent_opts(const od_tun_agent_opts_t *opts, od_tun_error_t *err) {
    size_t i = 0;
    if (err != NULL) {
        memset(err, 0, sizeof(*err));
    }
    if (opts == NULL) {
        tun_set_error(err, OD_TUN_ERR_INVALID_ARG, "agent options are null");
        return -1;
    }
    if (opts->allow_cidrs == NULL || opts->allow_cidr_count == 0) {
        tun_set_error(err, OD_TUN_ERR_ALLOW_CIDR_REQUIRED, "allow-cidr list is required");
        return -1;
    }
    if (opts->allow_ports == NULL || opts->allow_port_count == 0) {
        tun_set_error(err, OD_TUN_ERR_ALLOW_PORT_REQUIRED, "allow-port list is required");
        return -1;
    }
    for (i = 0; i < opts->allow_cidr_count; i++) {
        if (tun_validate_cidr_strict(opts->allow_cidrs[i], true, err, OD_TUN_ERR_ALLOW_CIDR_INVALID) != 0) {
            if (err != NULL && err->code == OD_TUN_ERR_ALLOW_CIDR_INVALID) {
                tun_set_error(err, OD_TUN_ERR_ALLOW_CIDR_INVALID, "invalid allow-cidr");
            }
            return -1;
        }
    }
    for (i = 0; i < opts->allow_port_count; i++) {
        if (tun_validate_port_spec(opts->allow_ports[i]) != 0) {
            tun_set_error(err, OD_TUN_ERR_ALLOW_PORT_INVALID, "invalid allow-port spec (expected tcp:PORT|udp:PORT)");
            return -1;
        }
    }
    return 0;
}

void od_tun_build_policy_from_agent_opts(const od_tun_agent_opts_t *opts, od_tun_policy_t *out) {
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (opts == NULL) {
        out->default_deny = true;
        return;
    }
    out->allow_cidr_count = opts->allow_cidr_count;
    out->allow_port_count = opts->allow_port_count;
    out->default_deny = true;
}

int od_tun_policy_is_default_deny(const od_tun_policy_t *policy) {
    if (policy == NULL) {
        return 1;
    }
    return policy->default_deny ? 1 : 0;
}
