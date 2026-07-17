#ifndef PROFILE_TASKS_H
#define PROFILE_TASKS_H

#include "ipad_errors.h"
#include "task_store.h"

ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out);
ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out);

#endif
