#include "worker_process.h"

#include "ipad_socket.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void worker_process_init(worker_process_t *process) {
    if (!process) {
        return;
    }
    process->pid = -1;
    process->stdin_fd = -1;
    process->stdout_fd = -1;
    process->ready = 0;
}

int worker_process_start(worker_process_t *process, const char *worker_path) {
    int to_worker[2];
    int from_worker[2];
    char ready[256];

    if (!process || !worker_path) {
        return -1;
    }
    worker_process_init(process);
    if (pipe(to_worker) != 0) {
        return -1;
    }
    if (pipe(from_worker) != 0) {
        close(to_worker[0]);
        close(to_worker[1]);
        return -1;
    }

    process->pid = fork();
    if (process->pid < 0) {
        close(to_worker[0]);
        close(to_worker[1]);
        close(from_worker[0]);
        close(from_worker[1]);
        return -1;
    }
    if (process->pid == 0) {
        dup2(to_worker[0], STDIN_FILENO);
        dup2(from_worker[1], STDOUT_FILENO);
        close(to_worker[0]);
        close(to_worker[1]);
        close(from_worker[0]);
        close(from_worker[1]);
        execl(worker_path, worker_path, "--sdk-mode", "mock", (char *)NULL);
        _exit(127);
    }

    close(to_worker[0]);
    close(from_worker[1]);
    process->stdin_fd = to_worker[1];
    process->stdout_fd = from_worker[0];

    if (ipad_socket_read_line(process->stdout_fd, ready, sizeof(ready)) != 0 ||
        !strstr(ready, "worker.ready")) {
        worker_process_stop(process);
        return -1;
    }
    process->ready = 1;
    return 0;
}

int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size) {
    if (!process || !process->ready || !request || !response || response_size == 0) {
        return -1;
    }
    if (ipad_socket_write_line(process->stdin_fd, request) != 0) {
        return -1;
    }
    return ipad_socket_read_line(process->stdout_fd, response, response_size);
}

int worker_process_stop(worker_process_t *process) {
    int status;

    if (!process) {
        return 0;
    }
    if (process->stdin_fd >= 0) {
        close(process->stdin_fd);
        process->stdin_fd = -1;
    }
    if (process->stdout_fd >= 0) {
        close(process->stdout_fd);
        process->stdout_fd = -1;
    }
    if (process->pid > 0) {
        kill(process->pid, SIGTERM);
        waitpid(process->pid, &status, 0);
        process->pid = -1;
    }
    process->ready = 0;
    return 0;
}
