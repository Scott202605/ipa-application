#include "worker_process.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    worker_process_t process;
    char response[512];

    if (argc != 2) {
        return 2;
    }
    worker_process_init(&process);
    if (worker_process_start(&process, argv[1], "mock", 10000) != 0) {
        fprintf(stderr, "worker start failed\n");
        return 1;
    }
    if (worker_process_call(&process, "{\"id\":1,\"op\":\"profile.enable\",\"task_id\":\"task-1\",\"iccid\":\"89860123456789012345\"}", response, sizeof(response), 10000) != 0) {
        worker_process_stop(&process);
        return 1;
    }
    worker_process_stop(&process);
    if (!strstr(response, "\"ok\":true")) {
        fprintf(stderr, "unexpected response: %s\n", response);
        return 1;
    }
    return 0;
}
