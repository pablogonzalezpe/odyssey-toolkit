#ifndef OD_KNOCK_H
#define OD_KNOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *host;
    const uint16_t *ports;
    size_t port_count;
    int delay_ms;
    int timeout_ms;
    bool verbose;
} od_knock_plan_t;

int od_run_knock(const od_knock_plan_t *plan);

#endif
