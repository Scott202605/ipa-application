#include "worker_supervisor.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    worker_supervisor_t supervisor;

    worker_supervisor_init(&supervisor);
    if (worker_supervisor_status(&supervisor) != WORKER_NOT_STARTED) {
        fprintf(stderr, "expected not started\n");
        return 1;
    }
    if (worker_supervisor_start_mock(&supervisor) != 0) {
        fprintf(stderr, "mock worker start failed\n");
        return 1;
    }
    if (worker_supervisor_status(&supervisor) != WORKER_READY) {
        fprintf(stderr, "expected ready\n");
        return 1;
    }
    if (strcmp(worker_status_to_string(WORKER_READY), "ready") != 0) {
        fprintf(stderr, "status string mismatch\n");
        return 1;
    }
    if (strcmp(worker_supervisor_sdk_mode(&supervisor), "mock") != 0) {
        fprintf(stderr, "sdk mode mismatch\n");
        return 1;
    }
    if (strcmp(worker_supervisor_last_error(&supervisor), "") != 0) {
        fprintf(stderr, "last error mismatch\n");
        return 1;
    }
    if (worker_supervisor_stop(&supervisor) != 0) {
        fprintf(stderr, "mock worker stop failed\n");
        return 1;
    }
    if (worker_supervisor_status(&supervisor) != WORKER_NOT_STARTED) {
        fprintf(stderr, "expected stopped\n");
        return 1;
    }
    return 0;
}
