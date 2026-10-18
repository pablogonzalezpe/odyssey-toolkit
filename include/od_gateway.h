#ifndef OD_GATEWAY_H
#define OD_GATEWAY_H

#include <stdbool.h>

#include "od_hardening.h"
#include "od_tls.h"
#include "od_tun.h"
#include "od_types.h"

typedef struct {
    endpoint_t control_listen_ep;
    const char *token;
    od_tun_gateway_opts_t tun_opts;
    od_hardening_options_t hardening_opts;
    od_tls_options_t tls_opts;
    const endpoint_t *admin_listen_ep;
    const char *admin_token;
    bool control_admin_enabled;
    bool control_admin_require_token;
    const char *control_admin_token;
    int control_admin_rate_limit_per_min;
    int heartbeat_ms;
    int heartbeat_timeout_ms;
    bool verbose;
} od_gateway_run_opts_t;

int od_run_gateway(const od_gateway_run_opts_t *opts);

#endif
