#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <time.h>
#endif

#include "od_hardening.h"
#include "od_log.h"
#include "od_socket.h"

typedef enum {
    OD_SRC_RULE_EXACT = 0,
    OD_SRC_RULE_CIDR4 = 1
} source_rule_kind_t;

typedef struct {
    source_rule_kind_t kind;
    char raw[256];
    uint32_t network;
    uint32_t mask;
} source_rule_t;

typedef struct {
    char ip[NI_MAXHOST];
    uint64_t window_start_ms;
    uint32_t connection_count;
    size_t knock_next_idx;
    uint64_t knock_last_ms;
    uint64_t knock_open_until_ms;
} source_state_t;

struct od_hardening_state {
    source_rule_t *rules;
    size_t rule_count;
    int rate_limit_per_min;
    uint16_t *knock_ports;
    size_t knock_count;
    int knock_timeout_ms;
    int knock_open_ms;
    bool verbose;
    source_state_t *sources;
    size_t source_count;
    size_t source_cap;
};

static uint64_t hard_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

static int parse_ipv4_to_u32(const char *ip, uint32_t *out) {
    struct in_addr addr;
    if (ip == NULL || out == NULL) {
        return -1;
    }
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return -1;
    }
    *out = ntohl(addr.s_addr);
    return 0;
}

static int parse_source_rule(const char *spec, source_rule_t *out_rule) {
    const char *slash = NULL;
    size_t ip_len = 0;
    char ip_part[64];
    unsigned long prefix = 0;
    char *endptr = NULL;
    uint32_t ip_u32 = 0;

    if (spec == NULL || out_rule == NULL || spec[0] == '\0') {
        return -1;
    }
    memset(out_rule, 0, sizeof(*out_rule));
    snprintf(out_rule->raw, sizeof(out_rule->raw), "%s", spec);

    slash = strchr(spec, '/');
    if (slash == NULL) {
        out_rule->kind = OD_SRC_RULE_EXACT;
        return 0;
    }

    ip_len = (size_t)(slash - spec);
    if (ip_len == 0 || ip_len >= sizeof(ip_part) || *(slash + 1) == '\0') {
        return -1;
    }
    memcpy(ip_part, spec, ip_len);
    ip_part[ip_len] = '\0';

    if (parse_ipv4_to_u32(ip_part, &ip_u32) != 0) {
        return -1;
    }

    prefix = strtoul(slash + 1, &endptr, 10);
    if (endptr == slash + 1 || *endptr != '\0' || prefix > 32UL) {
        return -1;
    }

    out_rule->kind = OD_SRC_RULE_CIDR4;
    if (prefix == 0UL) {
        out_rule->mask = 0U;
    } else {
        out_rule->mask = 0xFFFFFFFFU << (32U - (uint32_t)prefix);
    }
    out_rule->network = ip_u32 & out_rule->mask;
    return 0;
}

int od_hardening_validate_source_spec(const char *spec) {
    source_rule_t tmp;
    return parse_source_rule(spec, &tmp);
}

static bool source_matches_rule(const source_rule_t *rule, const char *ip) {
    uint32_t ip_u32 = 0;
    if (rule->kind == OD_SRC_RULE_EXACT) {
        return strcmp(rule->raw, ip) == 0;
    }
    if (parse_ipv4_to_u32(ip, &ip_u32) != 0) {
        return false;
    }
    return (ip_u32 & rule->mask) == rule->network;
}

static bool source_allowed(const od_hardening_state_t *state, const char *ip) {
    size_t i = 0;
    if (state->rule_count == 0) {
        return true;
    }
    for (i = 0; i < state->rule_count; i++) {
        if (source_matches_rule(&state->rules[i], ip)) {
            return true;
        }
    }
    return false;
}

static source_state_t *find_or_add_source(od_hardening_state_t *state, const char *ip) {
    size_t i = 0;
    source_state_t *next = NULL;

    for (i = 0; i < state->source_count; i++) {
        if (strcmp(state->sources[i].ip, ip) == 0) {
            return &state->sources[i];
        }
    }

    if (state->source_count == state->source_cap) {
        size_t new_cap = (state->source_cap == 0) ? 32 : (state->source_cap * 2);
        source_state_t *new_sources =
            (source_state_t *)realloc(state->sources, new_cap * sizeof(*state->sources));
        if (new_sources == NULL) {
            return NULL;
        }
        state->sources = new_sources;
        state->source_cap = new_cap;
    }

    next = &state->sources[state->source_count++];
    memset(next, 0, sizeof(*next));
    snprintf(next->ip, sizeof(next->ip), "%s", ip);
    return next;
}

int od_hardening_init(od_hardening_state_t **out_state, const od_hardening_options_t *opts,
                      char *err_buf, size_t err_buf_sz) {
    od_hardening_state_t *state = NULL;
    size_t i = 0;

    if (out_state == NULL) {
        return -1;
    }
    *out_state = NULL;

    state = (od_hardening_state_t *)calloc(1, sizeof(*state));
    if (state == NULL) {
        if (err_buf != NULL && err_buf_sz > 0) {
            snprintf(err_buf, err_buf_sz, "out of memory");
        }
        return -1;
    }

    if (opts != NULL) {
        state->rate_limit_per_min = opts->rate_limit_per_min;
        state->knock_timeout_ms = opts->knock_timeout_ms;
        state->knock_open_ms = opts->knock_open_ms;
        state->verbose = opts->verbose;

        if (opts->allow_source_count > 0) {
            state->rules = (source_rule_t *)calloc(opts->allow_source_count, sizeof(*state->rules));
            if (state->rules == NULL) {
                if (err_buf != NULL && err_buf_sz > 0) {
                    snprintf(err_buf, err_buf_sz, "out of memory");
                }
                od_hardening_free(state);
                return -1;
            }
            state->rule_count = opts->allow_source_count;
            for (i = 0; i < opts->allow_source_count; i++) {
                if (parse_source_rule(opts->allow_sources[i], &state->rules[i]) != 0) {
                    if (err_buf != NULL && err_buf_sz > 0) {
                        snprintf(err_buf, err_buf_sz, "invalid --allow-source: %s",
                                 opts->allow_sources[i]);
                    }
                    od_hardening_free(state);
                    return -1;
                }
            }
        }

        if (opts->knock_count > 0) {
            if (opts->knock_timeout_ms <= 0 || opts->knock_open_ms <= 0) {
                if (err_buf != NULL && err_buf_sz > 0) {
                    snprintf(err_buf, err_buf_sz, "knock timings must be > 0");
                }
                od_hardening_free(state);
                return -1;
            }
            state->knock_ports = (uint16_t *)calloc(opts->knock_count, sizeof(*state->knock_ports));
            if (state->knock_ports == NULL) {
                if (err_buf != NULL && err_buf_sz > 0) {
                    snprintf(err_buf, err_buf_sz, "out of memory");
                }
                od_hardening_free(state);
                return -1;
            }
            state->knock_count = opts->knock_count;
            memcpy(state->knock_ports, opts->knock_ports, opts->knock_count * sizeof(uint16_t));
        }
    }

    if (state->verbose) {
        od_log_info("hardening enabled allow_sources=%lu rate_limit_per_min=%d knock_seq_len=%lu",
                    (unsigned long)state->rule_count, state->rate_limit_per_min,
                    (unsigned long)state->knock_count);
    }

    *out_state = state;
    return 0;
}

void od_hardening_free(od_hardening_state_t *state) {
    if (state == NULL) {
        return;
    }
    free(state->rules);
    free(state->knock_ports);
    free(state->sources);
    free(state);
}

bool od_hardening_is_enabled(const od_hardening_state_t *state) {
    if (state == NULL) {
        return false;
    }
    return state->rule_count > 0 || state->rate_limit_per_min > 0 || state->knock_count > 0;
}

bool od_hardening_has_knock(const od_hardening_state_t *state) {
    return state != NULL && state->knock_count > 0;
}

size_t od_hardening_knock_count(const od_hardening_state_t *state) {
    if (state == NULL) {
        return 0;
    }
    return state->knock_count;
}

uint16_t od_hardening_knock_port_at(const od_hardening_state_t *state, size_t idx) {
    if (state == NULL || idx >= state->knock_count) {
        return 0;
    }
    return state->knock_ports[idx];
}

void od_hardening_on_knock(od_hardening_state_t *state, const char *source_ip, uint16_t knock_port) {
    source_state_t *src = NULL;
    uint64_t now = 0;
    uint16_t expected_port = 0;

    if (state == NULL || source_ip == NULL || source_ip[0] == '\0' || state->knock_count == 0) {
        return;
    }
    if (!source_allowed(state, source_ip)) {
        return;
    }

    src = find_or_add_source(state, source_ip);
    if (src == NULL) {
        return;
    }

    now = hard_now_ms();
    if (src->knock_next_idx > 0 && (int)(now - src->knock_last_ms) > state->knock_timeout_ms) {
        src->knock_next_idx = 0;
    }

    expected_port = state->knock_ports[src->knock_next_idx];
    if (knock_port == expected_port) {
        src->knock_next_idx++;
    } else if (knock_port == state->knock_ports[0]) {
        src->knock_next_idx = 1;
    } else {
        src->knock_next_idx = 0;
    }
    src->knock_last_ms = now;

    if (src->knock_next_idx == state->knock_count) {
        src->knock_open_until_ms = now + (uint64_t)state->knock_open_ms;
        src->knock_next_idx = 0;
        od_log_info("port-knock unlocked source=%s open_ms=%d", source_ip, state->knock_open_ms);
    }
}

bool od_hardening_allow_connection(od_hardening_state_t *state, const char *source_ip,
                                   char *reason_buf, size_t reason_buf_sz) {
    source_state_t *src = NULL;
    uint64_t now = 0;

    if (reason_buf != NULL && reason_buf_sz > 0) {
        snprintf(reason_buf, reason_buf_sz, "ok");
    }

    if (state == NULL || !od_hardening_is_enabled(state)) {
        return true;
    }
    if (source_ip == NULL || source_ip[0] == '\0') {
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "unknown source");
        }
        return false;
    }
    if (!source_allowed(state, source_ip)) {
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "source not allowed");
        }
        return false;
    }

    src = find_or_add_source(state, source_ip);
    if (src == NULL) {
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "hardening state full");
        }
        return false;
    }

    now = hard_now_ms();
    if (state->knock_count > 0 && now > src->knock_open_until_ms) {
        if (reason_buf != NULL && reason_buf_sz > 0) {
            snprintf(reason_buf, reason_buf_sz, "knock required");
        }
        return false;
    }

    if (state->rate_limit_per_min > 0) {
        if ((int)(now - src->window_start_ms) >= 60000 || src->window_start_ms == 0) {
            src->window_start_ms = now;
            src->connection_count = 0;
        }
        if ((int)src->connection_count >= state->rate_limit_per_min) {
            if (reason_buf != NULL && reason_buf_sz > 0) {
                snprintf(reason_buf, reason_buf_sz, "rate limit exceeded");
            }
            return false;
        }
        src->connection_count++;
    }

    return true;
}
