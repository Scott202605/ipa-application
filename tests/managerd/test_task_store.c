#include "task_store.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    ipad_task_t task;
    ipad_task_t loaded;

    task_store_init();
    if (task_store_create("profile.download", &task) != 0) {
        fprintf(stderr, "create failed\n");
        return 1;
    }
    if (strcmp(task.method, "profile.download") != 0) {
        fprintf(stderr, "method mismatch\n");
        return 1;
    }
    if (task_store_update_state(task.task_id, TASK_RUNNING, "execute", "") != 0) {
        fprintf(stderr, "update failed\n");
        return 1;
    }
    if (task_store_get(task.task_id, &loaded) != 0) {
        fprintf(stderr, "get failed\n");
        return 1;
    }
    if (loaded.state != TASK_RUNNING || strcmp(loaded.stage, "execute") != 0) {
        fprintf(stderr, "state mismatch\n");
        return 1;
    }
    if (strcmp(task_state_to_string(TASK_COMPLETED), "completed") != 0) {
        fprintf(stderr, "state string mismatch\n");
        return 1;
    }
    return 0;
}
