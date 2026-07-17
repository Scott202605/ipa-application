#include "worker_process.h"

#include "ipad_socket.h"

#include <signal.h>
#include <poll.h>
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
    process->last_exit_status = 0;
    snprintf(process->sdk_mode, sizeof(process->sdk_mode), "%s", "mock");
    process->last_error[0] = '\0';
}

static void set_last_error(worker_process_t *process, const char *error) {
    if (process) {
        snprintf(process->last_error, sizeof(process->last_error), "%s", error ? error : "");
    }
}

static int wait_fd_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    int rc;

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    rc = poll(&pfd, 1, timeout_ms);
    return rc == 1 && (pfd.revents & POLLIN);
}

int worker_process_start(worker_process_t *process, const char *worker_path, const char *sdk_mode, int timeout_ms) {
    int to_worker[2];
    int from_worker[2];
    char ready[256];
    const char *mode = sdk_mode ? sdk_mode : "mock";

    if (!process || !worker_path) {
        return -1;
    }
    worker_process_init(process);
    snprintf(process->sdk_mode, sizeof(process->sdk_mode), "%s", mode);
    if (pipe(to_worker) != 0) {
        set_last_error(process, "pipe_failed");
        return -1;
    }
    if (pipe(from_worker) != 0) {
        close(to_worker[0]);
        close(to_worker[1]);
        set_last_error(process, "pipe_failed");
        return -1;
    }

    process->pid = fork();
    if (process->pid < 0) {
        close(to_worker[0]);
        close(to_worker[1]);
        close(from_worker[0]);
        close(from_worker[1]);
        set_last_error(process, "fork_failed");
        return -1;
    }
    if (process->pid == 0) {
        dup2(to_worker[0], STDIN_FILENO);
        dup2(from_worker[1], STDOUT_FILENO);
        close(to_worker[0]);
        close(to_worker[1]);
        close(from_worker[0]);
        close(from_worker[1]);
        execl(worker_path, worker_path, "--sdk-mode", mode, (char *)NULL);
        _exit(127);
    }

    close(to_worker[0]);
    close(from_worker[1]);
    process->stdin_fd = to_worker[1];
    process->stdout_fd = from_worker[0];

    if (!wait_fd_readable(process->stdout_fd, timeout_ms)) {
        set_last_error(process, "worker_timeout");
        worker_process_stop(process);
        return -1;
    }
    if (ipad_socket_read_line(process->stdout_fd, ready, sizeof(ready)) != 0 ||
        !strstr(ready, "worker.ready")) {
        set_last_error(process, "worker_start_failed");
        worker_process_stop(process);
        return -1;
    }
    process->ready = 1;
    return 0;
}

int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size, int timeout_ms) {
    if (!process || !process->ready || !request || !response || response_size == 0) {
        return -1;
    }
    if (ipad_socket_write_line(process->stdin_fd, request) != 0) {
        set_last_error(process, "worker_write_failed");
        return -1;
    }
    if (!wait_fd_readable(process->stdout_fd, timeout_ms)) {
        set_last_error(process, "worker_timeout");
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
        if (waitpid(process->pid, &status, 0) > 0) {
            process->last_exit_status = status;
        }
        process->pid = -1;
    }
    process->ready = 0;
    return 0;
}
