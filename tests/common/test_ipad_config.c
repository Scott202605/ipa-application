#include "ipad_config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    ipad_config_t config;
    char error[128];
    char path[256];
    FILE *file;

    ipad_config_defaults(&config);
    if (strcmp(config.sdk_mode, "mock") != 0) return 1;
    if (config.request_timeout_ms != 10000) return 1;

    snprintf(path, sizeof(path), "%s", "/tmp/ipad-config-test.json");
    file = fopen(path, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"real\",\"request_timeout_ms\":5000,\"worker_path\":\"/tmp/worker\",\"task_retention\":8}", file);
    fclose(file);

    if (ipad_config_load_file(path, &config, error, sizeof(error)) != 0) return 1;
    unlink(path);
    if (strcmp(config.sdk_mode, "real") != 0) return 1;
    if (strcmp(config.worker_path, "/tmp/worker") != 0) return 1;
    if (config.request_timeout_ms != 5000) return 1;
    if (config.task_retention != 8) return 1;
    return 0;
}
