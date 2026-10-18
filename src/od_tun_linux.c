#define _POSIX_C_SOURCE 200809L

#include "od_tun_dev.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void tun_set_err(char *err_buf, size_t err_buf_sz, const char *msg) {
    if (err_buf == NULL || err_buf_sz == 0) {
        return;
    }
    snprintf(err_buf, err_buf_sz, "%s", msg == NULL ? "unknown error" : msg);
}

static void tun_set_syserr(char *err_buf, size_t err_buf_sz, const char *prefix) {
    char ebuf[128];
    const char *emsg = strerror(errno);
    if (emsg == NULL) {
        emsg = "errno";
    }
    snprintf(ebuf, sizeof(ebuf), "%s: %s", prefix != NULL ? prefix : "error", emsg);
    tun_set_err(err_buf, err_buf_sz, ebuf);
}

static int run_cmd_ip(char *const argv[], char *err_buf, size_t err_buf_sz) {
    pid_t pid = 0;
    int st = 0;
    int rc = 0;
    void (*prev_sigchld)(int);

    prev_sigchld = signal(SIGCHLD, SIG_DFL);

    pid = fork();
    if (pid < 0) {
        signal(SIGCHLD, prev_sigchld);
        tun_set_syserr(err_buf, err_buf_sz, "fork(ip)");
        return -1;
    }
    if (pid == 0) {
        execvp("ip", argv);
        _exit(127);
    }
    for (;;) {
        rc = waitpid(pid, &st, 0);
        if (rc >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        signal(SIGCHLD, prev_sigchld);
        tun_set_syserr(err_buf, err_buf_sz, "waitpid(ip)");
        return -1;
    }
    signal(SIGCHLD, prev_sigchld);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        tun_set_err(err_buf, err_buf_sz, "ip command failed");
        return -1;
    }
    return 0;
}

static int classify_packet(const uint8_t *buf, size_t len) {
    uint8_t ver = 0;
    if (buf == NULL || len < 1) {
        return -1;
    }
    ver = (uint8_t)(buf[0] >> 4);
    if (ver == 4u || ver == 6u) {
        return 0;
    }
    return -1;
}

int od_tun_dev_open(od_tun_dev_t *dev, const char *ifname_hint, const char *cidr, int mtu,
                    char *err_buf, size_t err_buf_sz) {
    int fd = -1;
    struct ifreq ifr;
    char *cmd_link_up[] = {"ip", "link", "set", "dev", NULL, "up", NULL};
    char mtu_raw[16];
    char *cmd_link_mtu[] = {"ip", "link", "set", "dev", NULL, "mtu", mtu_raw, "up", NULL};
    char *cmd_addr_add[] = {"ip", "addr", "replace", NULL, "dev", NULL, NULL};

    if (dev == NULL || cidr == NULL || cidr[0] == '\0') {
        tun_set_err(err_buf, err_buf_sz, "invalid tun open arguments");
        return -1;
    }
    if (mtu < OD_TUN_MTU_MIN || mtu > OD_TUN_MTU_MAX) {
        tun_set_err(err_buf, err_buf_sz, "invalid tun mtu");
        return -1;
    }

    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;
    dev->mtu = mtu;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) {
            tun_set_err(err_buf, err_buf_sz, "open /dev/net/tun failed: CAP_NET_ADMIN required");
        } else {
            tun_set_syserr(err_buf, err_buf_sz, "open(/dev/net/tun)");
        }
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI);
    if (ifname_hint != NULL && ifname_hint[0] != '\0') {
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname_hint);
    }
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        if (errno == EPERM || errno == EACCES) {
            tun_set_err(err_buf, err_buf_sz, "TUNSETIFF failed: CAP_NET_ADMIN required");
        } else {
            tun_set_syserr(err_buf, err_buf_sz, "ioctl(TUNSETIFF)");
        }
        close(fd);
        return -1;
    }

    snprintf(dev->ifname, sizeof(dev->ifname), "%s", ifr.ifr_name);
    dev->fd = fd;
    dev->mtu = mtu;
    dev->active = true;

    snprintf(mtu_raw, sizeof(mtu_raw), "%d", mtu);
    cmd_link_mtu[4] = dev->ifname;
    cmd_addr_add[3] = (char *)cidr;
    cmd_addr_add[5] = dev->ifname;
    cmd_link_up[4] = dev->ifname;

    if (run_cmd_ip(cmd_link_mtu, err_buf, err_buf_sz) != 0 ||
        run_cmd_ip(cmd_addr_add, err_buf, err_buf_sz) != 0 ||
        run_cmd_ip(cmd_link_up, err_buf, err_buf_sz) != 0) {
        od_tun_dev_close(dev, true);
        return -1;
    }

    return 0;
}

void od_tun_dev_close(od_tun_dev_t *dev, bool delete_link) {
    char *cmd_link_del[] = {"ip", "link", "delete", "dev", NULL, NULL};
    if (dev == NULL) {
        return;
    }
    if (delete_link && dev->active && dev->ifname[0] != '\0') {
        char ignore_err[64];
        memset(ignore_err, 0, sizeof(ignore_err));
        cmd_link_del[4] = dev->ifname;
        (void)run_cmd_ip(cmd_link_del, ignore_err, sizeof(ignore_err));
    }
    if (dev->fd >= 0) {
        (void)close(dev->fd);
    }
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;
}

int od_tun_dev_read_packet(od_tun_dev_t *dev, uint8_t *buf, size_t buf_sz, size_t *out_len,
                           char *err_buf, size_t err_buf_sz) {
    ssize_t n = 0;
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (dev == NULL || dev->fd < 0 || !dev->active || buf == NULL || out_len == NULL) {
        tun_set_err(err_buf, err_buf_sz, "invalid tun read arguments");
        return -1;
    }
    if (buf_sz < OD_TUN_MAX_PACKET) {
        tun_set_err(err_buf, err_buf_sz, "tun read buffer too small");
        return -1;
    }
    n = read(dev->fd, buf, buf_sz);
    if (n <= 0) {
        tun_set_syserr(err_buf, err_buf_sz, "read(tun)");
        return -1;
    }
    if ((size_t)n > OD_TUN_MAX_PACKET) {
        tun_set_err(err_buf, err_buf_sz, "tun packet too large");
        return -1;
    }
    if (classify_packet(buf, (size_t)n) != 0) {
        tun_set_err(err_buf, err_buf_sz, "unsupported packet class (only IPv4/IPv6)");
        return -1;
    }
    *out_len = (size_t)n;
    return 0;
}

int od_tun_dev_write_packet(od_tun_dev_t *dev, const uint8_t *buf, size_t len,
                            char *err_buf, size_t err_buf_sz) {
    ssize_t n = 0;
    if (dev == NULL || dev->fd < 0 || !dev->active || buf == NULL) {
        tun_set_err(err_buf, err_buf_sz, "invalid tun write arguments");
        return -1;
    }
    if (len == 0 || len > OD_TUN_MAX_PACKET) {
        tun_set_err(err_buf, err_buf_sz, "invalid tun packet length");
        return -1;
    }
    if (classify_packet(buf, len) != 0) {
        tun_set_err(err_buf, err_buf_sz, "unsupported packet class (only IPv4/IPv6)");
        return -1;
    }
    n = write(dev->fd, buf, len);
    if (n < 0 || (size_t)n != len) {
        tun_set_syserr(err_buf, err_buf_sz, "write(tun)");
        return -1;
    }
    return 0;
}

static int write_procfs(const char *path, const char *value, char *err_buf, size_t err_buf_sz) {
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        char cur[16];
        FILE *rf = fopen(path, "r");
        if (rf != NULL) {
            memset(cur, 0, sizeof(cur));
            if (fgets(cur, sizeof(cur), rf) != NULL) {
                size_t len = strlen(cur);
                while (len > 0 && (cur[len - 1] == '\n' || cur[len - 1] == '\r')) {
                    cur[--len] = '\0';
                }
                if (strcmp(cur, value) == 0) {
                    fclose(rf);
                    return 0;
                }
            }
            fclose(rf);
        }
        tun_set_syserr(err_buf, err_buf_sz, path);
        return -1;
    }
    if (fputs(value, f) == EOF) {
        fclose(f);
        tun_set_syserr(err_buf, err_buf_sz, path);
        return -1;
    }
    fclose(f);
    return 0;
}

int od_tun_enable_ip_forward(char *err_buf, size_t err_buf_sz) {
    return write_procfs("/proc/sys/net/ipv4/ip_forward", "1", err_buf, err_buf_sz);
}

int od_tun_enable_proxy_arp(const char *ifname, char *err_buf, size_t err_buf_sz) {
    char path[128];
    if (ifname == NULL || ifname[0] == '\0') {
        tun_set_err(err_buf, err_buf_sz, "proxy_arp: empty interface name");
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/proxy_arp", ifname);
    return write_procfs(path, "1", err_buf, err_buf_sz);
}

int od_tun_enable_accept_local(const char *ifname, char *err_buf, size_t err_buf_sz) {
    char path[128];
    if (ifname == NULL || ifname[0] == '\0') {
        tun_set_err(err_buf, err_buf_sz, "accept_local: empty interface name");
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/accept_local", ifname);
    if (write_procfs(path, "1", err_buf, err_buf_sz) == 0) {
        return 0;
    }
    return write_procfs("/proc/sys/net/ipv4/conf/all/accept_local", "1", err_buf, err_buf_sz);
}

int od_tun_add_route(const char *cidr, const char *dev_name, char *err_buf, size_t err_buf_sz) {
    char *cmd[] = {"ip", "route", "replace", NULL, "dev", NULL, NULL};
    if (cidr == NULL || dev_name == NULL) {
        tun_set_err(err_buf, err_buf_sz, "add_route: null argument");
        return -1;
    }
    cmd[3] = (char *)cidr;
    cmd[5] = (char *)dev_name;
    return run_cmd_ip(cmd, err_buf, err_buf_sz);
}

#else

int od_tun_dev_open(od_tun_dev_t *dev, const char *ifname_hint, const char *cidr, int mtu,
                    char *err_buf, size_t err_buf_sz) {
    (void)dev;
    (void)ifname_hint;
    (void)cidr;
    (void)mtu;
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

void od_tun_dev_close(od_tun_dev_t *dev, bool delete_link) {
    (void)dev;
    (void)delete_link;
}

int od_tun_dev_read_packet(od_tun_dev_t *dev, uint8_t *buf, size_t buf_sz, size_t *out_len,
                           char *err_buf, size_t err_buf_sz) {
    (void)dev;
    (void)buf;
    (void)buf_sz;
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

int od_tun_dev_write_packet(od_tun_dev_t *dev, const uint8_t *buf, size_t len,
                            char *err_buf, size_t err_buf_sz) {
    (void)dev;
    (void)buf;
    (void)len;
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

int od_tun_enable_ip_forward(char *err_buf, size_t err_buf_sz) {
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

int od_tun_enable_proxy_arp(const char *ifname, char *err_buf, size_t err_buf_sz) {
    (void)ifname;
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

int od_tun_enable_accept_local(const char *ifname, char *err_buf, size_t err_buf_sz) {
    (void)ifname;
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

int od_tun_add_route(const char *cidr, const char *dev_name, char *err_buf, size_t err_buf_sz) {
    (void)cidr;
    (void)dev_name;
    if (err_buf != NULL && err_buf_sz > 0) {
        snprintf(err_buf, err_buf_sz, "TUN device support only available on Linux");
    }
    return -1;
}

#endif
