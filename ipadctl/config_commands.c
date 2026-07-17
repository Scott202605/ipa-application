#include "config_commands.h"

#include "diagnostics.h"
#include "ipad_config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH "/etc/ipad-manager/config.json"

typedef struct {
    char *data;
    size_t size;
    size_t used;
} json_writer_t;

static int json_append(json_writer_t *writer, const char *fmt, ...) {
    va_list args;
    int written;

    if (!writer || !writer->data || writer->used >= writer->size) {
        return -1;
    }

    va_start(args, fmt);
    written = vsnprintf(writer->data + writer->used, writer->size - writer->used, fmt, args);
    va_end(args);

    if (written < 0 || (size_t)written >= writer->size - writer->used) {
        return -1;
    }
    writer->used += (size_t)written;
    return 0;
}

static const char *resolved_config_path(const char *config_path) {
    return (config_path && config_path[0] != '\0') ? config_path : DEFAULT_CONFIG_PATH;
}

static void parent_dir(const char *path, char *out, size_t out_size) {
    const char *slash;
    size_t len;

    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (!path || path[0] == '\0') {
        return;
    }

    slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out, out_size, ".");
        return;
    }
    if (slash == path) {
        snprintf(out, out_size, "/");
        return;
    }
    len = (size_t)(slash - path);
    if (len >= out_size) {
        len = out_size - 1;
    }
    memcpy(out, path, len);
    out[len] = '\0';
}

static void add_access_check(diagnostic_check_t *check, const char *name, const char *path, int mode, const char *message, const char *suggestion) {
    if (access(path, mode) == 0) {
        diagnostic_check_set(check, name, 1, "info", message, "");
    } else {
        diagnostic_check_set(check, name, 0, "error", message, suggestion);
    }
}

static int append_check(json_writer_t *writer, const diagnostic_check_t *check, int first) {
    char check_json[640];

    if (diagnostic_write_check_json(check, check_json, sizeof(check_json)) != 0) {
        return -1;
    }
    return json_append(writer, "%s%s", first ? "" : ",", check_json);
}

int ipadctl_config_show_to_buffer(const char *config_path, char *out, size_t out_size) {
    ipad_config_t config;
    char error[160];
    json_writer_t writer = {out, out_size, 0};

    if (ipad_config_load_file(resolved_config_path(config_path), &config, error, sizeof(error)) != 0) {
        return snprintf(out, out_size, "{\"ok\":false,\"error\":\"%s\",\"config_path\":\"%s\"}\n",
                        error,
                        resolved_config_path(config_path)) > 0 ? 3 : 1;
    }

    if (json_append(&writer,
                    "{\"ok\":true,\"config_path\":\"%s\",\"config\":{"
                    "\"socket_path\":\"%s\","
                    "\"worker_path\":\"%s\","
                    "\"sdk_mode\":\"%s\","
                    "\"request_timeout_ms\":%d,"
                    "\"worker_max_restarts\":%d,"
                    "\"worker_restart_window_seconds\":%d,"
                    "\"sdk_transport\":\"%s\","
                    "\"at_device\":\"%s\","
                    "\"at_baudrate\":%d,"
                    "\"sdk_log_level\":\"%s\","
                    "\"task_store_path\":\"%s\","
                    "\"task_retention\":%d,"
                    "\"audit_log_path\":\"%s\"}}\n",
                    resolved_config_path(config_path),
                    config.socket_path,
                    config.worker_path,
                    config.sdk_mode,
                    config.request_timeout_ms,
                    config.worker_max_restarts,
                    config.worker_restart_window_seconds,
                    config.sdk_transport,
                    config.at_device,
                    config.at_baudrate,
                    config.sdk_log_level,
                    config.task_store_path,
                    config.task_retention,
                    config.audit_log_path) != 0) {
        return 1;
    }
    return 0;
}

int ipadctl_config_check_to_buffer(const char *config_path, char *out, size_t out_size) {
    ipad_config_t config;
    diagnostic_check_t checks[5];
    char error[160];
    char task_dir[256];
    char audit_dir[256];
    int ok = 1;
    int count = 0;
    int i;
    json_writer_t writer = {out, out_size, 0};

    if (ipad_config_load_file(resolved_config_path(config_path), &config, error, sizeof(error)) != 0) {
        diagnostic_check_set(&checks[0], "config.parse", 0, "error", error, "Fix the JSON config or pass --config with a valid file");
        if (json_append(&writer, "{\"ok\":false,\"config_path\":\"%s\",\"checks\":[", resolved_config_path(config_path)) != 0 ||
            append_check(&writer, &checks[0], 1) != 0 ||
            json_append(&writer, "]}\n") != 0) {
            return 1;
        }
        return 3;
    }

    diagnostic_check_set(&checks[count++], "config.parse", 1, "info", "config loaded", "");

    add_access_check(&checks[count++], "worker.executable", config.worker_path, X_OK, "worker executable is available", "Install ipad-sdk-worker or update worker_path");

    parent_dir(config.task_store_path, task_dir, sizeof(task_dir));
    add_access_check(&checks[count++], "task_store.directory", task_dir, W_OK, "task store directory is writable", "Create the task store directory and grant write permission to the service user");

    parent_dir(config.audit_log_path, audit_dir, sizeof(audit_dir));
    add_access_check(&checks[count++], "audit_log.directory", audit_dir, W_OK, "audit log directory is writable", "Create the audit log directory and grant write permission to the service user");

    if (strcmp(config.sdk_mode, "real") == 0 && strcmp(config.sdk_transport, "at_serial") == 0) {
        add_access_check(&checks[count++], "at.device", config.at_device, R_OK | W_OK, "AT serial device is accessible", "Check the AT device path and dialout permissions");
    }

    for (i = 0; i < count; ++i) {
        if (!checks[i].ok) {
            ok = 0;
        }
    }

    if (json_append(&writer, "{\"ok\":%s,\"config_path\":\"%s\",\"checks\":[", ok ? "true" : "false", resolved_config_path(config_path)) != 0) {
        return 1;
    }
    for (i = 0; i < count; ++i) {
        if (append_check(&writer, &checks[i], i == 0) != 0) {
            return 1;
        }
    }
    if (json_append(&writer, "]}\n") != 0) {
        return 1;
    }

    return ok ? 0 : 1;
}

int ipadctl_config_command(int argc, char **argv, const char *default_config_path) {
    const char *config_path = default_config_path;
    char output[4096];
    int rc;

    if (argc >= 3 && strcmp(argv[argc - 2], "--config") == 0) {
        config_path = argv[argc - 1];
        argc -= 2;
    }

    if (argc == 2 && strcmp(argv[0], "config") == 0 && strcmp(argv[1], "show") == 0) {
        rc = ipadctl_config_show_to_buffer(config_path, output, sizeof(output));
        fputs(output, rc == 0 ? stdout : stderr);
        return rc;
    }
    if (argc == 2 && strcmp(argv[0], "config") == 0 && strcmp(argv[1], "check") == 0) {
        rc = ipadctl_config_check_to_buffer(config_path, output, sizeof(output));
        fputs(output, rc == 0 ? stdout : stderr);
        return rc;
    }
    return 2;
}
