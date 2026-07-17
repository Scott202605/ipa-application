#include "ipad_config.h"

#include "ipad_json.h"

#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_size, const char *message) {
    if (error && error_size > 0) {
        snprintf(error, error_size, "%s", message ? message : "");
    }
}

void ipad_config_defaults(ipad_config_t *config) {
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(*config));
    snprintf(config->socket_path, sizeof(config->socket_path), "%s", "/run/ipad-manager/ipad-manager.sock");
    snprintf(config->worker_path, sizeof(config->worker_path), "%s", "/usr/local/bin/ipad-sdk-worker");
    snprintf(config->sdk_mode, sizeof(config->sdk_mode), "%s", "mock");
    config->request_timeout_ms = 10000;
    config->worker_max_restarts = 3;
    config->worker_restart_window_seconds = 60;
    snprintf(config->sdk_transport, sizeof(config->sdk_transport), "%s", "at_serial");
    snprintf(config->at_device, sizeof(config->at_device), "%s", "/dev/ttyUSB2");
    config->at_baudrate = 115200;
    snprintf(config->sdk_log_level, sizeof(config->sdk_log_level), "%s", "info");
    snprintf(config->task_store_path, sizeof(config->task_store_path), "%s", "/var/lib/ipad-manager/tasks.jsonl");
    config->task_retention = 256;
    snprintf(config->audit_log_path, sizeof(config->audit_log_path), "%s", "/var/log/ipad-manager/audit.jsonl");
}

static int validate_config(const ipad_config_t *config, char *error, size_t error_size) {
    if (!config) {
        set_error(error, error_size, "config is null");
        return -1;
    }
    if (strcmp(config->sdk_mode, "mock") != 0 && strcmp(config->sdk_mode, "real") != 0) {
        set_error(error, error_size, "sdk_mode must be mock or real");
        return -1;
    }
    if (config->request_timeout_ms < 1000 || config->request_timeout_ms > 120000) {
        set_error(error, error_size, "request_timeout_ms out of range");
        return -1;
    }
    if (config->task_retention < 1 || config->task_retention > 4096) {
        set_error(error, error_size, "task_retention out of range");
        return -1;
    }
    return 0;
}

int ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size) {
    FILE *file;
    char json[4096];
    size_t n;

    if (!config) {
        set_error(error, error_size, "config is null");
        return -1;
    }
    ipad_config_defaults(config);
    if (!path || path[0] == '\0') {
        return validate_config(config, error, error_size);
    }

    file = fopen(path, "rb");
    if (!file) {
        set_error(error, error_size, "config file not found");
        return -1;
    }
    n = fread(json, 1, sizeof(json) - 1, file);
    fclose(file);
    json[n] = '\0';

    ipad_json_get_string(json, "socket_path", config->socket_path, sizeof(config->socket_path));
    ipad_json_get_string(json, "worker_path", config->worker_path, sizeof(config->worker_path));
    ipad_json_get_string(json, "sdk_mode", config->sdk_mode, sizeof(config->sdk_mode));
    ipad_json_get_int(json, "request_timeout_ms", &config->request_timeout_ms);
    ipad_json_get_int(json, "worker_max_restarts", &config->worker_max_restarts);
    ipad_json_get_int(json, "worker_restart_window_seconds", &config->worker_restart_window_seconds);
    ipad_json_get_string(json, "sdk_transport", config->sdk_transport, sizeof(config->sdk_transport));
    ipad_json_get_string(json, "at_device", config->at_device, sizeof(config->at_device));
    ipad_json_get_int(json, "at_baudrate", &config->at_baudrate);
    ipad_json_get_string(json, "sdk_log_level", config->sdk_log_level, sizeof(config->sdk_log_level));
    ipad_json_get_string(json, "task_store_path", config->task_store_path, sizeof(config->task_store_path));
    ipad_json_get_int(json, "task_retention", &config->task_retention);
    ipad_json_get_string(json, "audit_log_path", config->audit_log_path, sizeof(config->audit_log_path));

    return validate_config(config, error, error_size);
}
