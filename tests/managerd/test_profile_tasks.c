#include "profile_tasks.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    ipad_task_t task;

    task_store_init();
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
