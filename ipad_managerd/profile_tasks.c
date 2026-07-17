#include "profile_tasks.h"

static ipad_error_t complete_mock_task(const char *method, ipad_task_t *out) {
    if (task_store_create(method, out) != 0) {
        return IPAD_ERR_INTERNAL;
    }
    task_store_update_state(out->task_id, TASK_RUNNING, "mock_worker_execute", "");
    task_store_update_state(out->task_id, TASK_COMPLETED, "completed", "");
    task_store_get(out->task_id, out);
    return IPAD_OK;
}

ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out) {
    if (!smdp || smdp[0] == '\0' || !matching_id || matching_id[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return complete_mock_task("profile.download", out);
}

ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return complete_mock_task("profile.enable", out);
}

ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return complete_mock_task("profile.disable", out);
}

ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return complete_mock_task("profile.delete", out);
}
