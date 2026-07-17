#ifndef WORKER_PROCESS_H
#define WORKER_PROCESS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    int stdin_fd;
    int stdout_fd;
    int ready;
    int last_exit_status;
    char sdk_mode[16];
    char last_error[64];
} worker_process_t;

void worker_process_init(worker_process_t *process);
int worker_process_start(worker_process_t *process, const char *worker_path, const char *sdk_mode, int timeout_ms);
int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size, int timeout_ms);
int worker_process_stop(worker_process_t *process);

#endif
