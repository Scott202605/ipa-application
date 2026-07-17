#include "ipad_socket.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int prepare_addr(const char *path, struct sockaddr_un *addr) {
    if (!path || !addr || strlen(path) >= sizeof(addr->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", path);
    return 0;
}

static int unlink_stale_socket(const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        errno = EEXIST;
        return -1;
    }
    return unlink(path);
}

int ipad_socket_listen(const char *path, int backlog) {
    int fd;
    struct sockaddr_un addr;

    if (prepare_addr(path, &addr) != 0) {
        return -1;
    }
    if (unlink_stale_socket(path) != 0) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ipad_socket_connect(const char *path) {
    int fd;
    struct sockaddr_un addr;

    if (prepare_addr(path, &addr) != 0) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ipad_socket_write_line(int fd, const char *message) {
    size_t len;
    size_t offset = 0;

    if (fd < 0 || !message) {
        return -1;
    }
    len = strlen(message);
    while (offset < len) {
        ssize_t written = write(fd, message + offset, len - offset);
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    if (len == 0 || message[len - 1] != '\n') {
        ssize_t written = write(fd, "\n", 1);
        if (written != 1) {
            return -1;
        }
    }
    return 0;
}

int ipad_socket_read_line(int fd, char *out, size_t out_size) {
    size_t used = 0;

    if (fd < 0 || !out || out_size == 0) {
        return -1;
    }
    while (used + 1 < out_size) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            return -1;
        }
        out[used++] = ch;
        if (ch == '\n') {
            break;
        }
    }
    out[used] = '\0';
    return used > 0 ? 0 : -1;
}

int ipad_socket_close(int fd) {
    return fd >= 0 ? close(fd) : 0;
}
