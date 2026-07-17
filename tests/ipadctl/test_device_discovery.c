#include "device_discovery.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int touch_file(const char *path) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    fclose(file);
    return 0;
}

int main(void) {
    const char *root = "/tmp/ipadctl-dev-test";
    char output[4096];

    mkdir(root, 0700);
    if (touch_file("/tmp/ipadctl-dev-test/ttyUSB0") != 0) return 1;
    if (touch_file("/tmp/ipadctl-dev-test/ttyACM1") != 0) return 1;
    if (touch_file("/tmp/ipadctl-dev-test/wwan0") != 0) return 1;
    if (touch_file("/tmp/ipadctl-dev-test/not-a-modem") != 0) return 1;

    if (ipadctl_device_list(root, output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"ok\":true")) return 1;
    if (!strstr(output, "/tmp/ipadctl-dev-test/ttyUSB0")) return 1;
    if (!strstr(output, "/tmp/ipadctl-dev-test/ttyACM1")) return 1;
    if (!strstr(output, "/tmp/ipadctl-dev-test/wwan0")) return 1;
    if (strstr(output, "not-a-modem")) return 1;
    if (!strstr(output, "\"count\":3")) return 1;

    unlink("/tmp/ipadctl-dev-test/ttyUSB0");
    unlink("/tmp/ipadctl-dev-test/ttyACM1");
    unlink("/tmp/ipadctl-dev-test/wwan0");
    unlink("/tmp/ipadctl-dev-test/not-a-modem");
    rmdir(root);
    return 0;
}
