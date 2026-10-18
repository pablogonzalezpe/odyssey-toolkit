#ifndef OD_RELAY_H
#define OD_RELAY_H

#include <stdbool.h>

#include "od_hardening.h"
#include "od_socket.h"
#include "od_types.h"

int od_relay_bidirectional(socket_t left_fd, socket_t right_fd, bool verbose);
int od_run_relay(const endpoint_t *listen_ep, const endpoint_t *target_ep, int connect_timeout_ms,
                 const od_hardening_options_t *hardening_opts, bool verbose);

#endif
