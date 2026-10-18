#ifndef OD_TYPES_H
#define OD_TYPES_H

#include <stdint.h>

typedef struct {
    char host[256];
    uint16_t port;
} endpoint_t;

#endif
