#ifndef OD_SHA1_H
#define OD_SHA1_H

#include <stddef.h>
#include <stdint.h>

void od_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

#endif
