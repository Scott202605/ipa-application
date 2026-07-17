#ifndef PROFILE_TASKS_H
#define PROFILE_TASKS_H

#include "ipad_errors.h"
#include "task_store.h"

typedef struct {
    const char *worker_path;
} profile_task_runtime_t;

void profile_task_set_runtime(profile_task_runtime_t runtime);

ipad_error_t profile_task_start_download_activation(const char *activation_code, ipad_task_t *out);
ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out);
ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out);

#endif
