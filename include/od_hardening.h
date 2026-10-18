#ifndef OD_HARDENING_H
#define OD_HARDENING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *const *allow_sources;
    size_t allow_source_count;
    int rate_limit_per_min;
    const uint16_t *knock_ports;
    size_t knock_count;
    int knock_timeout_ms;
    int knock_open_ms;
    bool verbose;
} od_hardening_options_t;

typedef struct od_hardening_state od_hardening_state_t;

int od_hardening_validate_source_spec(const char *spec);

int od_hardening_init(od_hardening_state_t **out_state, const od_hardening_options_t *opts,
                      char *err_buf, size_t err_buf_sz);
void od_hardening_free(od_hardening_state_t *state);

bool od_hardening_is_enabled(const od_hardening_state_t *state);
bool od_hardening_has_knock(const od_hardening_state_t *state);
size_t od_hardening_knock_count(const od_hardening_state_t *state);
uint16_t od_hardening_knock_port_at(const od_hardening_state_t *state, size_t idx);

void od_hardening_on_knock(od_hardening_state_t *state, const char *source_ip, uint16_t knock_port);
bool od_hardening_allow_connection(od_hardening_state_t *state, const char *source_ip,
                                   char *reason_buf, size_t reason_buf_sz);

#endif
