#include "ipad_socket.h"

#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *managerd_path;
    const char *ipadctl_path;
    const char *socket_path;
    pid_t daemon_pid;
    pid_t cli_pid;
    int daemon_status = 0;
    int cli_status = 0;

    if (argc != 4) {
        return 2;
    }
    managerd_path = argv[1];
    ipadctl_path = argv[2];
    socket_path = argv[3];

    unlink(socket_path);
    daemon_pid = fork();
    if (daemon_pid == 0) {
        execl(managerd_path, managerd_path, "--once", "--socket", socket_path, (char *)NULL);
        _exit(127);
    }

    usleep(200000);
    cli_pid = fork();
    if (cli_pid == 0) {
        execl(ipadctl_path, ipadctl_path, "--socket", socket_path, "status", (char *)NULL);
        _exit(127);
    }

    waitpid(cli_pid, &cli_status, 0);
    waitpid(daemon_pid, &daemon_status, 0);
    unlink(socket_path);

    if (!WIFEXITED(cli_status) || WEXITSTATUS(cli_status) != 0) {
        fprintf(stderr, "ipadctl exited with status %d\n", cli_status);
        return 1;
    }
    if (!WIFEXITED(daemon_status) || WEXITSTATUS(daemon_status) != 0) {
        fprintf(stderr, "managerd exited with status %d\n", daemon_status);
        return 1;
    }
    return 0;
}
