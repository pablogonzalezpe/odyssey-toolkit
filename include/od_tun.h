#ifndef OD_TUN_H
#define OD_TUN_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    OD_TUN_ERR_NONE = 0,
    OD_TUN_ERR_INVALID_ARG = 1,
    OD_TUN_ERR_TUN_NAME_REQUIRED = 2,
    OD_TUN_ERR_TUN_CIDR_REQUIRED = 3,
    OD_TUN_ERR_TUN_CIDR_INVALID = 4,
    OD_TUN_ERR_ROUTE_ALLOW_REQUIRED = 5,
    OD_TUN_ERR_ROUTE_ALLOW_INVALID = 6,
    OD_TUN_ERR_ALLOW_CIDR_REQUIRED = 7,
    OD_TUN_ERR_ALLOW_CIDR_INVALID = 8,
    OD_TUN_ERR_ALLOW_PORT_REQUIRED = 9,
    OD_TUN_ERR_ALLOW_PORT_INVALID = 10,
    OD_TUN_ERR_DEFAULT_ROUTE_NOT_ALLOWED = 11,
    OD_TUN_ERR_GATEWAY_MTU_INVALID = 12
} od_tun_error_code_t;

typedef struct {
    od_tun_error_code_t code;
    char message[160];
} od_tun_error_t;

typedef struct {
    const char *tun_name;
    const char *tun_cidr;
    int gateway_mtu;
    const char *const *route_allow;
    size_t route_allow_count;
} od_tun_gateway_opts_t;

typedef struct {
    const char *agent_name;
    const char *const *allow_cidrs;
    size_t allow_cidr_count;
    const char *const *allow_ports;
    size_t allow_port_count;
} od_tun_agent_opts_t;

typedef struct {
    size_t allow_cidr_count;
    size_t allow_port_count;
    bool default_deny;
} od_tun_policy_t;

int od_tun_validate_gateway_opts(const od_tun_gateway_opts_t *opts, od_tun_error_t *err);
int od_tun_validate_agent_opts(const od_tun_agent_opts_t *opts, od_tun_error_t *err);
void od_tun_build_policy_from_agent_opts(const od_tun_agent_opts_t *opts, od_tun_policy_t *out);
int od_tun_policy_is_default_deny(const od_tun_policy_t *policy);

#endif
