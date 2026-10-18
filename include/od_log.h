#ifndef OD_LOG_H
#define OD_LOG_H

#include <stdint.h>

typedef enum {
    OD_LOG_FORMAT_TEXT = 0,
    OD_LOG_FORMAT_JSON = 1
} od_log_format_t;

void od_log_set_format(od_log_format_t fmt);
od_log_format_t od_log_get_format(void);

void od_log_info(const char *fmt, ...);
void od_log_warn(const char *fmt, ...);
void od_log_error(const char *fmt, ...);
void od_log_stream(const char *level, uint32_t stream_id, const char *fmt, ...);

#endif
