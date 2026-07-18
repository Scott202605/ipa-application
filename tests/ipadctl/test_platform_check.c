#include "platform_check.h"

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
    const char *root = "/tmp/ipadctl-platform-test";
    char out[4096];
    ipadctl_platform_info_t info;

    mkdir(root, 0700);
    mkdir("/tmp/ipadctl-platform-test/run", 0700);
    mkdir("/tmp/ipadctl-platform-test/run/systemd", 0700);
    mkdir("/tmp/ipadctl-platform-test/run/systemd/system", 0700);

    ipadctl_platform_detect(root, &info);
    if (info.init_system != IPADCTL_INIT_SYSTEMD) return 1;
    if (strcmp(ipadctl_init_system_name(info.init_system), "systemd") != 0) return 1;
    if (!strstr(ipadctl_restart_hint(info.init_system), "systemctl")) return 1;
    if (ipadctl_platform_report(root, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"init\":\"systemd\"")) return 1;
    if (!strstr(out, "\"support\":\"supported\"")) return 1;

    rmdir("/tmp/ipadctl-platform-test/run/systemd/system");
    rmdir("/tmp/ipadctl-platform-test/run/systemd");
    mkdir("/tmp/ipadctl-platform-test/sbin", 0700);
    if (touch_file("/tmp/ipadctl-platform-test/sbin/openrc-run") != 0) return 1;

    ipadctl_platform_detect(root, &info);
    if (info.init_system != IPADCTL_INIT_OPENRC) return 1;
    if (!strstr(ipadctl_restart_hint(info.init_system), "rc-service")) return 1;

    unlink("/tmp/ipadctl-platform-test/sbin/openrc-run");
    rmdir("/tmp/ipadctl-platform-test/sbin");
    rmdir("/tmp/ipadctl-platform-test/run");
    rmdir(root);
    return 0;
}
