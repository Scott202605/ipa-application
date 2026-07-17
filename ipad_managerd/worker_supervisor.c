#include "worker_supervisor.h"

#include <stdio.h>
#include <string.h>

void worker_supervisor_init(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return;
    }
    memset(supervisor, 0, sizeof(*supervisor));
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
    snprintf(supervisor->sdk_mode, sizeof(supervisor->sdk_mode), "%s", "mock");
    supervisor->last_error[0] = '\0';
}

int worker_supervisor_start_mock(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return -1;
    }
    supervisor->status = WORKER_READY;
    supervisor->pid = 1;
    snprintf(supervisor->sdk_mode, sizeof(supervisor->sdk_mode), "%s", "mock");
    supervisor->last_error[0] = '\0';
    return 0;
}

int worker_supervisor_stop(worker_supervisor_t *supervisor) {
    if (!supervisor) {
        return -1;
    }
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
    supervisor->last_error[0] = '\0';
    return 0;
}

worker_status_t worker_supervisor_status(worker_supervisor_t *supervisor) {
    return supervisor ? supervisor->status : WORKER_CRASHED;
}

const char *worker_supervisor_sdk_mode(worker_supervisor_t *supervisor) {
    return supervisor && supervisor->sdk_mode[0] ? supervisor->sdk_mode : "unknown";
}

const char *worker_supervisor_last_error(worker_supervisor_t *supervisor) {
    return supervisor && supervisor->last_error[0] ? supervisor->last_error : "";
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
