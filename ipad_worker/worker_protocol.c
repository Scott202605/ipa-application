#include "worker_protocol.h"

#include "ipad_json.h"

#include <stdio.h>
#include <string.h>

static int write_worker_ok(char *response, size_t response_size, int id, const char *task_id) {
    int written = snprintf(response, response_size,
                           "{\"id\":%d,\"ok\":true,\"task_id\":\"%s\",\"state\":\"completed\"}\n",
                           id,
                           task_id ? task_id : "");
    return written > 0 && (size_t)written < response_size ? 0 : -1;
}

static int write_worker_error(char *response, size_t response_size, int id, const char *task_id, ipad_error_t err) {
    int written = snprintf(response, response_size,
                           "{\"id\":%d,\"ok\":false,\"task_id\":\"%s\",\"error\":\"%s\"}\n",
                           id,
                           task_id ? task_id : "",
                           ipad_error_to_string(err));
    return written > 0 && (size_t)written < response_size ? 0 : -1;
}

static int write_sdk_init_ok(char *response, size_t response_size, int id, const sdk_adapter_t *adapter) {
    int written = snprintf(response, response_size,
                           "{\"id\":%d,\"ok\":true,\"sdk_mode\":\"%s\",\"initialized\":true}\n",
                           id,
                           sdk_adapter_mode(adapter));
    return written > 0 && (size_t)written < response_size ? 0 : -1;
}

static int write_sdk_status_ok(char *response, size_t response_size, int id, const char *status_json) {
    int written = snprintf(response, response_size,
                           "{\"id\":%d,\"ok\":true,\"status\":%s}\n",
                           id,
                           status_json ? status_json : "{}");
    return written > 0 && (size_t)written < response_size ? 0 : -1;
}

static int write_sdk_deinit_ok(char *response, size_t response_size, int id) {
    int written = snprintf(response, response_size,
                           "{\"id\":%d,\"ok\":true,\"initialized\":false}\n",
                           id);
    return written > 0 && (size_t)written < response_size ? 0 : -1;
}

int worker_protocol_handle_line(const char *request, char *response, size_t response_size, sdk_adapter_t *adapter) {
    int id = 0;
    char op[96];
    char task_id[32];
    char smdp[128];
    char matching_id[128];
    char iccid[64];
    ipad_error_t err = IPAD_ERR_METHOD_NOT_FOUND;

    if (ipad_json_get_int(request, "id", &id) != 0) {
        id = 0;
    }
    if (ipad_json_get_string(request, "task_id", task_id, sizeof(task_id)) != 0) {
        task_id[0] = '\0';
    }
    if (ipad_json_get_string(request, "op", op, sizeof(op)) != 0) {
        return write_worker_error(response, response_size, id, task_id, IPAD_ERR_BAD_REQUEST);
    }

    if (strcmp(op, "sdk.init") == 0) {
        char mode[32];
        if (ipad_json_get_string(request, "mode", mode, sizeof(mode)) != 0) {
            snprintf(mode, sizeof(mode), "%s", "mock");
        }
        err = sdk_adapter_init(adapter, mode);
        return err == IPAD_OK
                   ? write_sdk_init_ok(response, response_size, id, adapter)
                   : write_worker_error(response, response_size, id, task_id, err);
    } else if (strcmp(op, "sdk.status") == 0) {
        char status_json[256];
        err = sdk_adapter_sdk_status(adapter, status_json, sizeof(status_json));
        return err == IPAD_OK
                   ? write_sdk_status_ok(response, response_size, id, status_json)
                   : write_worker_error(response, response_size, id, task_id, err);
    } else if (strcmp(op, "sdk.deinit") == 0) {
        err = sdk_adapter_deinit(adapter);
        return err == IPAD_OK
                   ? write_sdk_deinit_ok(response, response_size, id)
                   : write_worker_error(response, response_size, id, task_id, err);
    } else if (strcmp(op, "profile.download") == 0) {
        if (ipad_json_get_string(request, "smdp", smdp, sizeof(smdp)) != 0 ||
            ipad_json_get_string(request, "matching_id", matching_id, sizeof(matching_id)) != 0) {
            err = IPAD_ERR_INVALID_PARAMS;
        } else {
            err = sdk_adapter_profile_download(adapter, smdp, matching_id);
        }
    } else if (strcmp(op, "profile.enable") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
                  ? sdk_adapter_profile_enable(adapter, iccid)
                  : IPAD_ERR_INVALID_PARAMS;
    } else if (strcmp(op, "profile.disable") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
                  ? sdk_adapter_profile_disable(adapter, iccid)
                  : IPAD_ERR_INVALID_PARAMS;
    } else if (strcmp(op, "profile.delete") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
                  ? sdk_adapter_profile_delete(adapter, iccid)
                  : IPAD_ERR_INVALID_PARAMS;
    }

    return err == IPAD_OK
               ? write_worker_ok(response, response_size, id, task_id)
               : write_worker_error(response, response_size, id, task_id, err);
}
