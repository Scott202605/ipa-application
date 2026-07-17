#include "rpc_server.h"

#include "audit_log.h"
#include "ipad_json.h"
#include "ipad_protocol.h"
#include "profile_tasks.h"
#include "worker_supervisor.h"

#include <stdio.h>
#include <string.h>

static worker_supervisor_t g_worker;
static int g_worker_initialized = 0;
static int g_task_store_initialized = 0;

static worker_supervisor_t *worker(void) {
    if (!g_worker_initialized) {
        worker_supervisor_init(&g_worker);
        g_worker_initialized = 1;
    }
    return &g_worker;
}

static void ensure_task_store(void) {
    if (!g_task_store_initialized) {
        task_store_init();
        g_task_store_initialized = 1;
    }
}

static int write_profile_task_result(char *response, size_t response_size, int id, const ipad_task_t *task) {
    char result[192];

    snprintf(result, sizeof(result),
             "{\"task_id\":\"%s\",\"state\":\"%s\"}",
             task->task_id,
             task_state_to_string(task->state));
    return ipad_json_write_result(response, response_size, id, result);
}

int rpc_handle_request(const char *request, char *response, size_t response_size) {
    char method[IPAD_MAX_METHOD_NAME];
    int id = 0;

    if (!request || !response || response_size == 0) {
        return -1;
    }
    if (ipad_json_get_int(request, "id", &id) != 0) {
        id = 0;
    }
    if (ipad_json_get_string(request, "method", method, sizeof(method)) != 0) {
        audit_log_write("local", "", "", "bad_request");
        return ipad_json_write_error(response, response_size, id, IPAD_ERR_BAD_REQUEST, "missing method");
    }

    if (strcmp(method, IPAD_METHOD_SYSTEM_STATUS) == 0) {
        char result[160];
        snprintf(result, sizeof(result),
                 "{\"daemon\":\"running\",\"worker\":\"%s\"}",
                 worker_status_to_string(worker_supervisor_status(worker())));
        audit_log_write("local", method, "", "ok");
        return ipad_json_write_result(response, response_size, id, result);
    }

    if (strcmp(method, IPAD_METHOD_WORKER_START_MOCK) == 0) {
        worker_supervisor_start_mock(worker());
        audit_log_write("local", method, "", "ok");
        return ipad_json_write_result(response, response_size, id, "{\"worker\":\"ready\"}");
    }

    if (strcmp(method, IPAD_METHOD_SDK_INIT) == 0) {
        audit_log_write("local", method, "", "ok");
        return ipad_json_write_result(response, response_size, id, "{\"sdk\":\"initialized\",\"mode\":\"mock\"}");
    }

    if (strcmp(method, IPAD_METHOD_SDK_STATUS) == 0) {
        audit_log_write("local", method, "", "ok");
        return ipad_json_write_result(response, response_size, id, "{\"mode\":\"mock\",\"initialized\":true}");
    }

    if (strcmp(method, IPAD_METHOD_SDK_DEINIT) == 0) {
        audit_log_write("local", method, "", "ok");
        return ipad_json_write_result(response, response_size, id, "{\"sdk\":\"deinitialized\"}");
    }

    ensure_task_store();
    if (strcmp(method, IPAD_METHOD_TASK_GET) == 0) {
        char task_id[IPAD_TASK_ID_SIZE];
        ipad_task_t task;
        char task_json[512];

        if (ipad_json_get_string(request, "task_id", task_id, sizeof(task_id)) != 0) {
            audit_log_write("local", method, "", "invalid_params");
            return ipad_json_write_error(response, response_size, id, IPAD_ERR_INVALID_PARAMS, "missing task_id");
        }
        if (task_store_get(task_id, &task) != 0) {
            audit_log_write("local", method, task_id, "task_not_found");
            return ipad_json_write_error(response, response_size, id, IPAD_ERR_TASK_NOT_FOUND, "task not found");
        }
        if (task_store_write_json(&task, task_json, sizeof(task_json)) != 0) {
            return ipad_json_write_error(response, response_size, id, IPAD_ERR_INTERNAL, "task serialization failed");
        }
        audit_log_write("local", method, task_id, "ok");
        return ipad_json_write_result(response, response_size, id, task_json);
    }

    if (strcmp(method, IPAD_METHOD_PROFILE_DOWNLOAD) == 0) {
        char activation_code[256];
        char smdp[128];
        char matching_id[128];
        ipad_task_t task;
        ipad_error_t err;

        if (ipad_json_get_string(request, "activation_code", activation_code, sizeof(activation_code)) == 0) {
            err = profile_task_start_download_activation(activation_code, &task);
        } else if (ipad_json_get_string(request, "smdp", smdp, sizeof(smdp)) == 0 &&
                   ipad_json_get_string(request, "matching_id", matching_id, sizeof(matching_id)) == 0) {
            err = profile_task_start_download(smdp, matching_id, &task);
        } else {
            audit_log_write("local", method, "", "invalid_params");
            return ipad_json_write_error(response, response_size, id, IPAD_ERR_INVALID_PARAMS, "missing activation_code or smdp/matching_id");
        }
        if (err != IPAD_OK) {
            audit_log_write("local", method, "", ipad_error_to_string(err));
            return ipad_json_write_error(response, response_size, id, err, ipad_error_to_string(err));
        }
        audit_log_write("local", method, task.task_id, "ok");
        return write_profile_task_result(response, response_size, id, &task);
    }

    if (strcmp(method, IPAD_METHOD_PROFILE_ENABLE) == 0 ||
        strcmp(method, IPAD_METHOD_PROFILE_DISABLE) == 0 ||
        strcmp(method, IPAD_METHOD_PROFILE_DELETE) == 0) {
        char iccid[64];
        ipad_task_t task;
        ipad_error_t err;

        if (ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) != 0) {
            audit_log_write("local", method, "", "invalid_params");
            return ipad_json_write_error(response, response_size, id, IPAD_ERR_INVALID_PARAMS, "missing iccid");
        }
        if (strcmp(method, IPAD_METHOD_PROFILE_ENABLE) == 0) {
            err = profile_task_start_enable(iccid, &task);
        } else if (strcmp(method, IPAD_METHOD_PROFILE_DISABLE) == 0) {
            err = profile_task_start_disable(iccid, &task);
        } else {
            err = profile_task_start_delete(iccid, &task);
        }
        if (err != IPAD_OK) {
            audit_log_write("local", method, "", ipad_error_to_string(err));
            return ipad_json_write_error(response, response_size, id, err, ipad_error_to_string(err));
        }
        audit_log_write("local", method, task.task_id, "ok");
        return write_profile_task_result(response, response_size, id, &task);
    }

    audit_log_write("local", method, "", "method_not_found");
    return ipad_json_write_error(response, response_size, id, IPAD_ERR_METHOD_NOT_FOUND, "unknown method");
}
