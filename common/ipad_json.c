#include "ipad_json.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ipad_error_to_string(ipad_error_t error) {
    switch (error) {
        case IPAD_OK: return "ok";
        case IPAD_ERR_BAD_REQUEST: return "bad_request";
        case IPAD_ERR_INVALID_PARAMS: return "invalid_params";
        case IPAD_ERR_METHOD_NOT_FOUND: return "method_not_found";
        case IPAD_ERR_WORKER_UNAVAILABLE: return "worker_unavailable";
        case IPAD_ERR_WORKER_CRASHED: return "worker_crashed";
        case IPAD_ERR_WORKER_TIMEOUT: return "worker_timeout";
        case IPAD_ERR_SDK_NOT_INITIALIZED: return "sdk_not_initialized";
        case IPAD_ERR_SDK_FAILED: return "sdk_failed";
        case IPAD_ERR_DEVICE_UNAVAILABLE: return "device_unavailable";
        case IPAD_ERR_TASK_NOT_FOUND: return "task_not_found";
        case IPAD_ERR_INTERNAL: return "internal_error";
        default: return "internal_error";
    }
}

static const char *find_json_value(const char *json, const char *key) {
    char pattern[128];
    const char *pos;
    const char *colon;

    if (!json || !key) {
        return NULL;
    }
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) >= (int)sizeof(pattern)) {
        return NULL;
    }

    pos = strstr(json, pattern);
    if (!pos) {
        return NULL;
    }
    colon = strchr(pos + strlen(pattern), ':');
    if (!colon) {
        return NULL;
    }
    colon++;
    while (*colon != '\0' && isspace((unsigned char)*colon)) {
        colon++;
    }
    return colon;
}

int ipad_json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    const char *start;
    const char *end;
    size_t len;

    if (!out || out_size == 0) {
        return -1;
    }
    out[0] = '\0';
    start = find_json_value(json, key);
    if (!start || *start != '"') {
        return -1;
    }
    start++;
    end = start;
    while (*end != '\0') {
        if (*end == '"' && (end == start || *(end - 1) != '\\')) {
            break;
        }
        end++;
    }
    if (*end != '"') {
        return -1;
    }

    len = (size_t)(end - start);
    if (len >= out_size) {
        len = out_size - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int ipad_json_get_int(const char *json, const char *key, int *out) {
    const char *value;
    char *end = NULL;
    long parsed;

    if (!out) {
        return -1;
    }
    value = find_json_value(json, key);
    if (!value) {
        return -1;
    }
    parsed = strtol(value, &end, 10);
    if (end == value) {
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

int ipad_json_write_error(char *out, size_t out_size, int id, ipad_error_t error, const char *message) {
    int written;

    if (!out || out_size == 0) {
        return -1;
    }
    written = snprintf(out, out_size,
                       "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":%d,\"name\":\"%s\",\"message\":\"%s\"}}\n",
                       id,
                       (int)error,
                       ipad_error_to_string(error),
                       message ? message : ipad_error_to_string(error));
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

int ipad_json_write_result(char *out, size_t out_size, int id, const char *result_json) {
    int written;

    if (!out || out_size == 0 || !result_json) {
        return -1;
    }
    written = snprintf(out, out_size,
                       "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":%s}\n",
                       id,
                       result_json);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}
