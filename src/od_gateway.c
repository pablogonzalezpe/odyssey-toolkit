#include "od_gateway.h"

#include <stddef.h>
#include <string.h>

#include "od_log.h"
#include "od_reverse.h"
#include "od_tun.h"
#include "od_tun_dev.h"

#define GATEWAY_MAX_STREAMS 128u

int od_run_gateway(const od_gateway_run_opts_t *opts) {
    od_admin_server_opts_t admin_opts;
    od_admin_server_opts_t *admin_opts_ptr = NULL;
    od_control_admin_policy_t policy;
    od_tun_error_t tun_err;
    od_tun_dev_t tun_dev;
    char tun_dev_err[256];
    int rc = 1;

    if (opts == NULL || opts->token == NULL || opts->token[0] == '\0') {
        od_log_error("gateway: invalid runtime options");
        return 1;
    }

    memset(&tun_err, 0, sizeof(tun_err));
    memset(&tun_dev, 0, sizeof(tun_dev));
    memset(tun_dev_err, 0, sizeof(tun_dev_err));
    memset(&admin_opts, 0, sizeof(admin_opts));
    tun_dev.fd = -1;
    if (od_tun_validate_gateway_opts(&opts->tun_opts, &tun_err) != 0) {
        od_log_error("gateway: tun policy validation failed: %s", tun_err.message);
        return 1;
    }

    memset(&policy, 0, sizeof(policy));
    policy.enabled = opts->control_admin_enabled;
    policy.require_token = opts->control_admin_require_token;
    policy.token = opts->control_admin_token;
    policy.max_binds = 0; /* gateway mode: disable legacy ADD_BIND/DEL_BIND */
    policy.rate_limit_per_min = opts->control_admin_rate_limit_per_min;

    if (opts->admin_listen_ep != NULL) {
        admin_opts.listen_ep = opts->admin_listen_ep;
        admin_opts.token = opts->admin_token;
        admin_opts_ptr = &admin_opts;
    }

    if (od_tun_dev_open(&tun_dev, opts->tun_opts.tun_name, opts->tun_opts.tun_cidr,
                        opts->tun_opts.gateway_mtu, tun_dev_err, sizeof(tun_dev_err)) != 0) {
        od_log_error("gateway: failed to create/configure TUN: %s", tun_dev_err);
        return 1;
    }

    od_log_info("gateway runtime listening on %s:%u tun=%s cidr=%s mtu=%d route_allow_count=%lu",
                opts->control_listen_ep.host, (unsigned)opts->control_listen_ep.port,
                tun_dev.ifname[0] != '\0' ? tun_dev.ifname :
                (opts->tun_opts.tun_name != NULL ? opts->tun_opts.tun_name : ""),
                opts->tun_opts.tun_cidr != NULL ? opts->tun_opts.tun_cidr : "",
                opts->tun_opts.gateway_mtu,
                (unsigned long)opts->tun_opts.route_allow_count);
    od_log_info("gateway runtime mode=dataplane-mvp (T1.7) tun_device=ready tun_runtime=packet-bridge");
    if (admin_opts_ptr != NULL && admin_opts.listen_ep != NULL) {
        od_log_info("gateway admin listener configured on %s:%u token=%s",
                    admin_opts.listen_ep->host, (unsigned)admin_opts.listen_ep->port,
                    admin_opts.token != NULL ? "required" : "disabled");
    }

    od_reverse_set_tun_gateway_ctx(tun_dev.fd, opts->tun_opts.route_allow, opts->tun_opts.route_allow_count);

    rc = od_run_reverse_server(&opts->control_listen_ep,
                               NULL, 0,
                               NULL,
                               GATEWAY_MAX_STREAMS,
                               opts->token,
                               &opts->hardening_opts,
                               admin_opts_ptr,
                               &policy,
                               &opts->tls_opts,
                               opts->heartbeat_ms,
                               opts->heartbeat_timeout_ms,
                               opts->verbose);
    od_reverse_clear_tun_gateway_ctx();
    od_tun_dev_close(&tun_dev, true);
    return rc;
}
