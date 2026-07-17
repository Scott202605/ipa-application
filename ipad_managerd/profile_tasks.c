#include "profile_tasks.h"

#include "worker_process.h"

#include <stdio.h>
#include <string.h>

static profile_task_runtime_t g_runtime = {0};

void profile_task_set_runtime(profile_task_runtime_t runtime) {
    g_runtime = runtime;
}

static ipad_error_t complete_mock_task(const char *method, ipad_task_t *out) {
    if (task_store_create(method, out) != 0) {
        return IPAD_ERR_INTERNAL;
    }
    task_store_update_state(out->task_id, TASK_RUNNING, "mock_worker_execute", "");
    task_store_update_state(out->task_id, TASK_COMPLETED, "completed", "");
    task_store_get(out->task_id, out);
    return IPAD_OK;
}

static ipad_error_t execute_worker_task(ipad_task_t *out, const char *request) {
    worker_process_t worker;
    char response[512];

    worker_process_init(&worker);
    if (worker_process_start(&worker, g_runtime.worker_path) != 0) {
        task_store_update_state(out->task_id, TASK_FAILED, "worker_start", "worker_unavailable");
        task_store_get(out->task_id, out);
        return IPAD_ERR_WORKER_UNAVAILABLE;
    }
    task_store_update_state(out->task_id, TASK_RUNNING, "worker_execute", "");
    if (worker_process_call(&worker, request, response, sizeof(response)) != 0) {
        worker_process_stop(&worker);
        task_store_update_state(out->task_id, TASK_FAILED, "worker_execute", "worker_failed");
        task_store_get(out->task_id, out);
        return IPAD_ERR_WORKER_CRASHED;
    }
    worker_process_stop(&worker);
    if (!strstr(response, "\"ok\":true")) {
        task_store_update_state(out->task_id, TASK_FAILED, "worker_execute", "sdk_failed");
        task_store_get(out->task_id, out);
        return IPAD_ERR_SDK_FAILED;
    }
    task_store_update_state(out->task_id, TASK_COMPLETED, "completed", "");
    task_store_get(out->task_id, out);
    return IPAD_OK;
}

static ipad_error_t create_task_for_runtime(const char *method, ipad_task_t *out) {
    if (!g_runtime.worker_path) {
        return complete_mock_task(method, out);
    }
    if (task_store_create(method, out) != 0) {
        return IPAD_ERR_INTERNAL;
    }
    return IPAD_OK;
}

ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out) {
    char request[512];
    ipad_error_t err;

    if (!smdp || smdp[0] == '\0' || !matching_id || matching_id[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    err = create_task_for_runtime("profile.download", out);
    if (err != IPAD_OK) return err;
    if (!g_runtime.worker_path) return IPAD_OK;
    snprintf(request, sizeof(request),
             "{\"id\":1,\"op\":\"profile.download\",\"task_id\":\"%s\",\"smdp\":\"%s\",\"matching_id\":\"%s\"}",
             out->task_id,
             smdp,
             matching_id);
    return execute_worker_task(out, request);
}

ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out) {
    char request[512];
    ipad_error_t err;

    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    err = create_task_for_runtime("profile.enable", out);
    if (err != IPAD_OK) return err;
    if (!g_runtime.worker_path) return IPAD_OK;
    snprintf(request, sizeof(request),
             "{\"id\":1,\"op\":\"profile.enable\",\"task_id\":\"%s\",\"iccid\":\"%s\"}",
             out->task_id,
             iccid);
    return execute_worker_task(out, request);
}

ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out) {
    char request[512];
    ipad_error_t err;

    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    err = create_task_for_runtime("profile.disable", out);
    if (err != IPAD_OK) return err;
    if (!g_runtime.worker_path) return IPAD_OK;
    snprintf(request, sizeof(request),
             "{\"id\":1,\"op\":\"profile.disable\",\"task_id\":\"%s\",\"iccid\":\"%s\"}",
             out->task_id,
             iccid);
    return execute_worker_task(out, request);
}

ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out) {
    char request[512];
    ipad_error_t err;

    if (!iccid || iccid[0] == '\0' || !out) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    err = create_task_for_runtime("profile.delete", out);
    if (err != IPAD_OK) return err;
    if (!g_runtime.worker_path) return IPAD_OK;
    snprintf(request, sizeof(request),
             "{\"id\":1,\"op\":\"profile.delete\",\"task_id\":\"%s\",\"iccid\":\"%s\"}",
             out->task_id,
             iccid);
    return execute_worker_task(out, request);
}
