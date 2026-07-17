#include "worker_supervisor.h"

#include <string.h>

void worker_supervisor_init(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return;
    }
    memset(supervisor, 0, sizeof(*supervisor));
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
}

int worker_supervisor_start_mock(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return -1;
    }
    supervisor->status = WORKER_READY;
    supervisor->pid = 1;
    return 0;
}

int worker_supervisor_stop(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return -1;
    }
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
    return 0;
}

worker_status_t worker_supervisor_status(worker_supervisor_t *supervisor) {
    return supervisor ? supervisor->status : WORKER_CRASHED;
}

const char *worker_status_to_string(worker_status_t status) {
    switch (status) {
        case WORKER_NOT_STARTED: return "not_started";
        case WORKER_STARTING: return "starting";
        case WORKER_READY: return "ready";
        case WORKER_BUSY: return "busy";
        case WORKER_CRASHED: return "crashed";
        default: return "unknown";
    }
}
