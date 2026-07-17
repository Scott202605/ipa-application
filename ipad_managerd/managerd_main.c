#include "rpc_server.h"

#include "ipad_protocol.h"
#include "ipad_socket.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int serve_once(int listen_fd) {
    int client_fd;
    char request[IPAD_MAX_JSON_MESSAGE];
    char response[IPAD_MAX_JSON_MESSAGE];

    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        return 1;
    }
    if (ipad_socket_read_line(client_fd, request, sizeof(request)) != 0) {
        ipad_socket_close(client_fd);
        return 1;
    }
    if (rpc_handle_request(request, response, sizeof(response)) != 0) {
        ipad_socket_close(client_fd);
        return 1;
    }
    if (ipad_socket_write_line(client_fd, response) != 0) {
        ipad_socket_close(client_fd);
        return 1;
    }
    ipad_socket_close(client_fd);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s [--once] [--socket <path>]\n", argv0);
}

int main(int argc, char **argv) {
    const char *socket_path = IPAD_DEFAULT_SOCKET_PATH;
    bool once = false;
    int listen_fd;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--once") == 0) {
            once = true;
        } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    listen_fd = ipad_socket_listen(socket_path, 8);
    if (listen_fd < 0) {
        perror("ipad_socket_listen");
        return 1;
    }

    if (once) {
        int rc = serve_once(listen_fd);
        ipad_socket_close(listen_fd);
        return rc;
    }

    for (;;) {
        if (serve_once(listen_fd) != 0) {
            break;
        }
    }
    ipad_socket_close(listen_fd);
    return 0;
}
