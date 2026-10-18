#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <time.h>
#endif

#include "od_knock.h"
#include "od_log.h"
#include "od_socket.h"
#include "od_types.h"

static void knock_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

int od_run_knock(const od_knock_plan_t *plan) {
    size_t i = 0;

    if (plan == NULL || plan->host == NULL || plan->host[0] == '\0' ||
        plan->ports == NULL || plan->port_count == 0) {
        od_log_error("invalid knock plan");
        return -1;
    }

    for (i = 0; i < plan->port_count; i++) {
        endpoint_t ep;
        socket_t fd = OD_SOCK_INVALID;
        char reason[160];
        memset(&ep, 0, sizeof(ep));
        memset(reason, 0, sizeof(reason));
        snprintf(ep.host, sizeof(ep.host), "%s", plan->host);
        ep.port = plan->ports[i];

        if (plan->verbose) {
            od_log_info("knock %lu/%lu -> %s:%u", (unsigned long)(i + 1),
                        (unsigned long)plan->port_count, ep.host, (unsigned)ep.port);
        }

        fd = od_connect_to_target_ex(&ep, plan->timeout_ms, reason, sizeof(reason));
        if (fd == OD_SOCK_INVALID) {
            od_log_warn("knock failed on %s:%u (%s)", ep.host, (unsigned)ep.port, reason);
            return -1;
        }
        od_socket_close(fd);

        if (plan->delay_ms > 0 && (i + 1) < plan->port_count) {
            knock_sleep_ms(plan->delay_ms);
        }
    }

    if (plan->verbose) {
        od_log_info("knock sequence complete host=%s count=%lu",
                    plan->host, (unsigned long)plan->port_count);
    }
    return 0;
}
