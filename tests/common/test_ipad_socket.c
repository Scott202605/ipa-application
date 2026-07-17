#include "ipad_socket.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        return 1;
    }
    return 0;
}

int main(void) {
    int pair[2];
    char buffer[128];

    if (require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair failed")) return 1;
    if (require(ipad_socket_write_line(pair[0], "{\"ok\":true}") == 0, "write failed")) return 1;
    if (require(ipad_socket_read_line(pair[1], buffer, sizeof(buffer)) == 0, "read failed")) return 1;
    if (require(strcmp(buffer, "{\"ok\":true}\n") == 0, "line mismatch")) return 1;
    close(pair[0]);
    close(pair[1]);
    return 0;
}
