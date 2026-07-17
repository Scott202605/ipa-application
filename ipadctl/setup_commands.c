#include "setup_commands.h"

#include <stdio.h>
#include <string.h>

#define DEFAULT_CONFIG_PATH "/etc/ipad-manager/config.json"

static const char *resolved_config_path(const char *config_path) {
    return (config_path && config_path[0] != '\0') ? config_path : DEFAULT_CONFIG_PATH;
}

static int write_text_file(const char *path, const char *text) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    if (fputs(text, file) < 0) {
        fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

int ipadctl_setup_mock(const char *config_path, char *out, size_t out_size) {
    const char *path = resolved_config_path(config_path);
    const char *json =
        "{\n"
        "  \"socket_path\": \"/run/ipad-manager/ipad-manager.sock\",\n"
        "  \"worker_path\": \"/usr/local/bin/ipad-sdk-worker\",\n"
        "  \"sdk_mode\": \"mock\",\n"
        "  \"request_timeout_ms\": 10000,\n"
        "  \"worker_max_restarts\": 3,\n"
        "  \"worker_restart_window_seconds\": 60,\n"
        "  \"sdk_transport\": \"at_serial\",\n"
        "  \"at_device\": \"/dev/ttyUSB2\",\n"
        "  \"at_baudrate\": 115200,\n"
        "  \"sdk_log_level\": \"info\",\n"
        "  \"task_store_path\": \"/var/lib/ipad-manager/tasks.jsonl\",\n"
        "  \"task_retention\": 256,\n"
        "  \"audit_log_path\": \"/var/log/ipad-manager/audit.jsonl\"\n"
        "}\n";

    if (write_text_file(path, json) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config\",\"suggestion\":\"Run with sudo or choose --config <writable-path>\"}\n");
        return 1;
    }
    snprintf(out, out_size, "{\"ok\":true,\"created\":\"%s\",\"sdk_mode\":\"mock\",\"next_action\":\"Run: sudo systemctl restart ipad-managerd && ipadctl doctor\"}\n", path);
    return 0;
}

int ipadctl_setup_real_at(const char *config_path, const char *at_device, char *out, size_t out_size) {
    char json[1536];
    const char *path = resolved_config_path(config_path);

    if (!at_device || at_device[0] == '\0') {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"missing at device\",\"suggestion\":\"Run: ipadctl device list\"}\n");
        return 2;
    }

    if (snprintf(json, sizeof(json),
                 "{\n"
                 "  \"socket_path\": \"/run/ipad-manager/ipad-manager.sock\",\n"
                 "  \"worker_path\": \"/usr/local/bin/ipad-sdk-worker\",\n"
                 "  \"sdk_mode\": \"real\",\n"
                 "  \"request_timeout_ms\": 10000,\n"
                 "  \"worker_max_restarts\": 3,\n"
                 "  \"worker_restart_window_seconds\": 60,\n"
                 "  \"sdk_transport\": \"at_serial\",\n"
                 "  \"at_device\": \"%s\",\n"
                 "  \"at_baudrate\": 115200,\n"
                 "  \"sdk_log_level\": \"info\",\n"
                 "  \"task_store_path\": \"/var/lib/ipad-manager/tasks.jsonl\",\n"
                 "  \"task_retention\": 256,\n"
                 "  \"audit_log_path\": \"/var/log/ipad-manager/audit.jsonl\"\n"
                 "}\n",
                 at_device) >= (int)sizeof(json)) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"config template too large\"}\n");
        return 1;
    }

    if (write_text_file(path, json) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config\",\"suggestion\":\"Run with sudo or choose --config <writable-path>\"}\n");
        return 1;
    }
    snprintf(out, out_size, "{\"ok\":true,\"created\":\"%s\",\"sdk_mode\":\"real\",\"at_device\":\"%s\",\"next_action\":\"Run: sudo systemctl restart ipad-managerd && ipadctl doctor\"}\n", path, at_device);
    return 0;
}

int ipadctl_setup_command(int argc, char **argv, const char *default_config_path) {
    const char *config_path = default_config_path;
    const char *at_device = NULL;
    char output[2048];
    int i;
    int mock = 0;
    int real = 0;
    int rc;

    if (argc < 2 || strcmp(argv[0], "setup") != 0) {
        return 2;
    }

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mock") == 0) {
            mock = 1;
        } else if (strcmp(argv[i], "--real") == 0) {
            real = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--at-device") == 0 && i + 1 < argc) {
            at_device = argv[++i];
        } else {
            return 2;
        }
    }

    if (mock == real) {
        return 2;
    }

    rc = mock ? ipadctl_setup_mock(config_path, output, sizeof(output))
              : ipadctl_setup_real_at(config_path, at_device, output, sizeof(output));
    fputs(output, rc == 0 ? stdout : stderr);
    return rc;
}
