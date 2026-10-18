#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "od_log.h"

static od_log_format_t g_log_format = OD_LOG_FORMAT_TEXT;

void od_log_set_format(od_log_format_t fmt) {
    g_log_format = fmt;
}

od_log_format_t od_log_get_format(void) {
    return g_log_format;
}

static const char *normalize_level(const char *level_or_prefix) {
    if (strcmp(level_or_prefix, "[*]") == 0) {
        return "info";
    }
    if (strcmp(level_or_prefix, "[!]") == 0) {
        return "warn";
    }
    if (strcmp(level_or_prefix, "[-]") == 0) {
        return "error";
    }
    return level_or_prefix;
}

static void write_json_escaped(FILE *f, const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p != '\0') {
        if (*p == '\\' || *p == '"') {
            fputc('\\', f);
            fputc((int)*p, f);
        } else if (*p == '\n') {
            fputs("\\n", f);
        } else if (*p == '\r') {
            fputs("\\r", f);
        } else if (*p == '\t') {
            fputs("\\t", f);
        } else if (*p < 32U) {
            fprintf(f, "\\u%04x", (unsigned int)*p);
        } else {
            fputc((int)*p, f);
        }
        p++;
    }
}

static void od_log_v(const char *level_or_prefix, const char *fmt, va_list ap) {
    char msg[2048];
    const char *level = normalize_level(level_or_prefix);
    int n = vsnprintf(msg, sizeof(msg), fmt, ap);
    if (n < 0) {
        snprintf(msg, sizeof(msg), "log formatting error");
    }
    msg[sizeof(msg) - 1] = '\0';

    if (g_log_format == OD_LOG_FORMAT_JSON) {
        fputs("{\"level\":\"", stderr);
        write_json_escaped(stderr, level);
        fputs("\",\"msg\":\"", stderr);
        write_json_escaped(stderr, msg);
        fputs("\"}\n", stderr);
        return;
    }

    fprintf(stderr, "%s %s\n", level_or_prefix, msg);
}

void od_log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    od_log_v("[*]", fmt, ap);
    va_end(ap);
}

void od_log_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    od_log_v("[!]", fmt, ap);
    va_end(ap);
}

void od_log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    od_log_v("[-]", fmt, ap);
    va_end(ap);
}

void od_log_stream(const char *level, uint32_t stream_id, const char *fmt, ...) {
    va_list ap;
    char merged_fmt[256];
    int n = snprintf(merged_fmt, sizeof(merged_fmt), "stream=%lu %s",
                     (unsigned long)stream_id, fmt);
    if (n <= 0 || (size_t)n >= sizeof(merged_fmt)) {
        snprintf(merged_fmt, sizeof(merged_fmt), "stream=%lu %s",
                 (unsigned long)stream_id, "event");
    }
    va_start(ap, fmt);
    od_log_v(level, merged_fmt, ap);
    va_end(ap);
}
