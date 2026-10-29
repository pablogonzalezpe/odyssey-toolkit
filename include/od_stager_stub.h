#ifndef OD_STAGER_STUB_H
#define OD_STAGER_STUB_H

#include <stdint.h>
#include <stddef.h>

int od_stager_generate_stub_disk(const char *host, uint16_t port, const char *run_args);
int od_stager_generate_stub_shm(const char *host, uint16_t port, const char *run_args);
int od_stager_generate_stub_memfd(const char *host, uint16_t port, const char *run_args);
int od_stager_generate_perl_memfd(const char *host, uint16_t port, const char *run_args);
void od_stager_print_formats(const char *os_filter);

#endif
