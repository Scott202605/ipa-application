#ifndef WORKER_SUPERVISOR_H
#define WORKER_SUPERVISOR_H

typedef enum {
    WORKER_NOT_STARTED = 0,
    WORKER_STARTING = 1,
    WORKER_READY = 2,
    WORKER_BUSY = 3,
    WORKER_CRASHED = 4
} worker_status_t;

typedef struct {
    worker_status_t status;
    int pid;
    int restart_count;
} worker_supervisor_t;

void worker_supervisor_init(worker_supervisor_t *supervisor);
int worker_supervisor_start_mock(worker_supervisor_t *supervisor);
int worker_supervisor_stop(worker_supervisor_t *supervisor);
worker_status_t worker_supervisor_status(worker_supervisor_t *supervisor);
const char *worker_status_to_string(worker_status_t status);

#endif
