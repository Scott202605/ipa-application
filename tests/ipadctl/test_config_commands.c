#include "config_commands.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int write_file(const char *path, const char *content) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    fputs(content, file);
    fclose(file);
    return 0;
}

int main(void) {
    char output[4096];
    const char *valid_path = "/tmp/ipadctl-config-valid.json";
    const char *bad_path = "/tmp/ipadctl-config-bad.json";

    if (write_file(valid_path,
                   "{\"sdk_mode\":\"mock\","
                   "\"worker_path\":\"/bin/sh\","
                   "\"task_store_path\":\"/tmp/ipad-manager-tasks.jsonl\","
                   "\"audit_log_path\":\"/tmp/ipad-manager-audit.jsonl\"}") != 0) {
        return 1;
    }
    if (write_file(bad_path, "{\"sdk_mode\":\"invalid\"}") != 0) {
        unlink(valid_path);
        return 1;
    }

    if (ipadctl_config_show_to_buffer(valid_path, output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"ok\":true")) return 1;
    if (!strstr(output, "\"worker_path\":\"/bin/sh\"")) return 1;

    if (ipadctl_config_check_to_buffer(valid_path, output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"name\":\"worker.executable\"")) return 1;
    if (!strstr(output, "\"ok\":true")) return 1;

    if (ipadctl_config_check_to_buffer(bad_path, output, sizeof(output)) != 3) return 1;
    if (!strstr(output, "\"name\":\"config.parse\"")) return 1;
    if (!strstr(output, "\"ok\":false")) return 1;

    unlink(valid_path);
    unlink(bad_path);
    return 0;
}
