#ifndef OD_TUN_DEV_H
#define OD_TUN_DEV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OD_TUN_DEFAULT_MTU 1400
#define OD_TUN_MTU_MIN 576
#define OD_TUN_MTU_MAX 9000
#define OD_TUN_MAX_PACKET 2000

typedef struct {
    int fd;
    char ifname[64];
    int mtu;
    bool active;
} od_tun_dev_t;

int od_tun_dev_open(od_tun_dev_t *dev, const char *ifname_hint, const char *cidr, int mtu,
                    char *err_buf, size_t err_buf_sz);
void od_tun_dev_close(od_tun_dev_t *dev, bool delete_link);

int od_tun_dev_read_packet(od_tun_dev_t *dev, uint8_t *buf, size_t buf_sz, size_t *out_len,
                           char *err_buf, size_t err_buf_sz);
int od_tun_dev_write_packet(od_tun_dev_t *dev, const uint8_t *buf, size_t len,
                            char *err_buf, size_t err_buf_sz);

int od_tun_enable_ip_forward(char *err_buf, size_t err_buf_sz);
int od_tun_enable_proxy_arp(const char *ifname, char *err_buf, size_t err_buf_sz);
int od_tun_enable_accept_local(const char *ifname, char *err_buf, size_t err_buf_sz);
int od_tun_add_route(const char *cidr, const char *dev_name, char *err_buf, size_t err_buf_sz);

#endif
