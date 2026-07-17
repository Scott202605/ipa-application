#include "task_store.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    ipad_task_t task;
    ipad_task_t loaded;
    char path[256];

    snprintf(path, sizeof(path), "%s", "/tmp/ipad-task-store-test.jsonl");
    unlink(path);
    task_store_init();
    if (task_store_set_path(path, 16) != 0) return 1;
    if (task_store_create("profile.download", &task) != 0) return 1;
    if (task_store_update_state(task.task_id, TASK_COMPLETED, "sdk.profile.download", "") != 0) return 1;
    task_store_init();
    if (task_store_set_path(path, 16) != 0) return 1;
    if (task_store_load() != 0) return 1;
    if (task_store_get(task.task_id, &loaded) != 0) return 1;
    unlink(path);
    if (loaded.state != TASK_COMPLETED) return 1;
    if (strcmp(loaded.stage, "sdk.profile.download") != 0) return 1;
    return 0;
}
