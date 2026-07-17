#ifndef IPAD_SOCKET_H
#define IPAD_SOCKET_H

#include <stddef.h>

int ipad_socket_listen(const char *path, int backlog);
int ipad_socket_connect(const char *path);
int ipad_socket_write_line(int fd, const char *message);
int ipad_socket_read_line(int fd, char *out, size_t out_size);
int ipad_socket_close(int fd);

#endif
