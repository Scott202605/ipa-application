#include "profile_tasks.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    ipad_task_t task;

    task_store_init();
    if (argc == 2) {
        profile_task_set_runtime((profile_task_runtime_t){.worker_path = argv[1]});
    } else {
        profile_task_set_runtime((profile_task_runtime_t){0});
    }

    if (profile_task_start_download("smdp.example.com", "ABCD", &task) != IPAD_OK) return 1;
    if (strcmp(task.method, "profile.download") != 0) return 1;
    if (task.state != TASK_COMPLETED) return 1;
    if (profile_task_start_enable("89860123456789012345", &task) != IPAD_OK) return 1;
    if (strcmp(task.method, "profile.enable") != 0) return 1;
    if (task.state != TASK_COMPLETED) return 1;
    if (profile_task_start_disable("89860123456789012345", &task) != IPAD_OK) return 1;
    if (profile_task_start_delete("", &task) != IPAD_ERR_INVALID_PARAMS) return 1;
    return 0;
}
