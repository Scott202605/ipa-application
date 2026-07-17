#include "ipad_socket.h"

#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *managerd_path;
    const char *socket_path;
    pid_t pid;
    int fd;
    char response[512];
    int status = 0;

    if (argc != 3) {
        return 2;
    }
    managerd_path = argv[1];
    socket_path = argv[2];

    unlink(socket_path);
    pid = fork();
    if (pid == 0) {
        execl(managerd_path, managerd_path, "--once", "--socket", socket_path, (char *)NULL);
        _exit(127);
    }

    usleep(200000);
    fd = ipad_socket_connect(socket_path);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    if (ipad_socket_write_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}") != 0) {
        return 1;
    }
    if (ipad_socket_read_line(fd, response, sizeof(response)) != 0) {
        return 1;
    }
    ipad_socket_close(fd);
    waitpid(pid, &status, 0);
    unlink(socket_path);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "managerd exited with status %d\n", status);
        return 1;
    }
    if (!strstr(response, "\"daemon\":\"running\"")) {
        fprintf(stderr, "unexpected response: %s\n", response);
        return 1;
    }
    return 0;
}
