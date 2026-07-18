#include "bootstrap_commands.h"

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
    const char *systemd_root = "/tmp/ipadctl-bootstrap-systemd";
    const char *openrc_root = "/tmp/ipadctl-bootstrap-openrc";
    char out[4096];

    mkdir(systemd_root, 0700);
    mkdir("/tmp/ipadctl-bootstrap-systemd/run", 0700);
    mkdir("/tmp/ipadctl-bootstrap-systemd/run/systemd", 0700);
    mkdir("/tmp/ipadctl-bootstrap-systemd/run/systemd/system", 0700);

    if (ipadctl_bootstrap_check(systemd_root, "mock", NULL, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "setup --mock")) return 1;
    if (!strstr(out, "systemctl restart ipad-managerd")) return 1;
    if (!strstr(out, "ipadctl doctor")) return 1;

    mkdir(openrc_root, 0700);
    mkdir("/tmp/ipadctl-bootstrap-openrc/sbin", 0700);
    if (touch_file("/tmp/ipadctl-bootstrap-openrc/sbin/openrc-run") != 0) return 1;

    if (ipadctl_bootstrap_check(openrc_root, "real", "/dev/ttyUSB2", out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "setup --real --at-device /dev/ttyUSB2")) return 1;
    if (!strstr(out, "rc-service ipad-managerd restart")) return 1;
    if (!strstr(out, "\"init\":\"openrc\"")) return 1;

    if (ipadctl_bootstrap_check(openrc_root, "real", NULL, out, sizeof(out)) != 2) return 1;
    if (!strstr(out, "ipadctl device list")) return 1;

    rmdir("/tmp/ipadctl-bootstrap-systemd/run/systemd/system");
    rmdir("/tmp/ipadctl-bootstrap-systemd/run/systemd");
    rmdir("/tmp/ipadctl-bootstrap-systemd/run");
    rmdir(systemd_root);
    unlink("/tmp/ipadctl-bootstrap-openrc/sbin/openrc-run");
    rmdir("/tmp/ipadctl-bootstrap-openrc/sbin");
    rmdir(openrc_root);
    return 0;
}
