#ifndef OD_REVERSE_H
#define OD_REVERSE_H

#include <stdbool.h>
#include <stddef.h>

#include "od_hardening.h"
#include "od_knock.h"
#include "od_types.h"
#include "od_tls.h"

typedef struct {
    endpoint_t listen_ep;
    endpoint_t target_ep;
} od_bind_rule_t;

typedef struct {
    const endpoint_t *listen_ep;
    const char *username;
    const char *password;
} od_socks_server_opts_t;

typedef struct {
    const endpoint_t *listen_ep;
    const char *token;
} od_admin_server_opts_t;

typedef struct {
    bool enabled;
    bool require_token;
    const char *token;
    size_t max_binds;
    int rate_limit_per_min;
} od_control_admin_policy_t;

typedef enum {
    OD_CTRL_ACTION_LIST_BIND = 1,
    OD_CTRL_ACTION_ADD_BIND = 2,
    OD_CTRL_ACTION_DEL_BIND = 3,
    OD_CTRL_ACTION_CAPABILITIES = 4,
    OD_CTRL_ACTION_STATUS = 5,
    OD_CTRL_ACTION_LIST_STREAM = 6,
    OD_CTRL_ACTION_CLOSE_STREAM = 7,
    OD_CTRL_ACTION_TUN_ROUTE_LIST = 8,
    OD_CTRL_ACTION_TUN_ROUTE_ADD = 9,
    OD_CTRL_ACTION_TUN_ROUTE_DEL = 10,
    OD_CTRL_ACTION_TUN_POLICY_SHOW = 11,
    OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_ADD = 12,
    OD_CTRL_ACTION_TUN_POLICY_ALLOW_CIDR_DEL = 13,
    OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_ADD = 14,
    OD_CTRL_ACTION_TUN_POLICY_ALLOW_PORT_DEL = 15,
    OD_CTRL_ACTION_TUN_KILLSWITCH = 16,
    OD_CTRL_ACTION_SNAPSHOT = 17
} od_ctrl_action_type_t;

typedef struct {
    od_ctrl_action_type_t type;
    char value[1024];
} od_ctrl_action_t;

typedef struct {
    const od_ctrl_action_t *actions;
    size_t action_count;
    bool exit_after_actions;
    const char *admin_token;
} od_ctrl_client_opts_t;

typedef struct {
    const char *agent_name;
    const char *const *allow_cidrs;
    size_t allow_cidr_count;
    const char *const *allow_ports;
    size_t allow_port_count;
    const char *agent_tun_cidr;
    const char *agent_tun_name;
    int agent_tun_mtu;
} od_tun_agent_runtime_opts_t;

int od_run_reverse_server(const endpoint_t *control_listen_ep, const od_bind_rule_t *bind_rules,
                          size_t bind_count, const od_socks_server_opts_t *socks_opts,
                          size_t max_streams, const char *token,
                          const od_hardening_options_t *hardening_opts,
                          const od_admin_server_opts_t *admin_opts,
                          const od_control_admin_policy_t *control_admin_policy,
                          const od_tls_options_t *tls_opts,
                          int heartbeat_ms, int heartbeat_timeout_ms, bool verbose);
int od_run_reverse_client(const endpoint_t *connect_ep, const endpoint_t *allow_targets,
                          size_t allow_target_count, size_t max_streams,
                          const char *token, int connect_timeout_ms,
                          const od_knock_plan_t *knock_plan,
                          const od_ctrl_client_opts_t *ctrl_opts,
                          const od_tls_options_t *tls_opts,
                          int heartbeat_timeout_ms, bool verbose);
int od_run_tun_agent(const endpoint_t *connect_ep, const char *token,
                     const od_tun_agent_runtime_opts_t *tun_opts,
                     int connect_timeout_ms, const od_knock_plan_t *knock_plan,
                     const od_tls_options_t *tls_opts,
                     int heartbeat_timeout_ms, bool verbose);
void od_reverse_set_tun_gateway_ctx(int tun_fd, const char *const *route_allow,
                                    size_t route_allow_count);
void od_reverse_clear_tun_gateway_ctx(void);

#endif
