#include "ipad_config.h"
#include "setup_commands.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    ipad_config_t config;
    char output[2048];
    char error[160];
    const char *mock_path = "/tmp/ipadctl-setup-mock.json";
    const char *real_path = "/tmp/ipadctl-setup-real.json";

    if (ipadctl_setup_mock(mock_path, output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"sdk_mode\":\"mock\"")) return 1;
    if (ipad_config_load_file(mock_path, &config, error, sizeof(error)) != 0) return 1;
    if (strcmp(config.sdk_mode, "mock") != 0) return 1;

    if (ipadctl_setup_real_at(real_path, "/dev/ttyUSB9", output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"at_device\":\"/dev/ttyUSB9\"")) return 1;
    if (ipad_config_load_file(real_path, &config, error, sizeof(error)) != 0) return 1;
    if (strcmp(config.sdk_mode, "real") != 0) return 1;
    if (strcmp(config.at_device, "/dev/ttyUSB9") != 0) return 1;

    if (ipadctl_setup_real_at(real_path, NULL, output, sizeof(output)) != 2) return 1;
    if (!strstr(output, "ipadctl device list")) return 1;

    unlink(mock_path);
    unlink(real_path);
    return 0;
}
