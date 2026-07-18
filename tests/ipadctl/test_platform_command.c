#include "platform_check.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    const char *root = "/tmp/ipadctl-platform-command";
    char *argv[] = {"platform", "check", "--root", (char *)root};
    char output[4096];

    mkdir(root, 0700);
    mkdir("/tmp/ipadctl-platform-command/run", 0700);
    mkdir("/tmp/ipadctl-platform-command/run/systemd", 0700);
    mkdir("/tmp/ipadctl-platform-command/run/systemd/system", 0700);

    if (ipadctl_platform_report(root, output, sizeof(output)) != 0) return 1;
    if (!strstr(output, "\"platform\"")) return 1;
    if (!strstr(output, "\"checks\"")) return 1;
    if (!strstr(output, "\"next_action\":\"Run: ipadctl doctor\"")) return 1;
    if (ipadctl_platform_command(4, argv) != 0) return 1;

    rmdir("/tmp/ipadctl-platform-command/run/systemd/system");
    rmdir("/tmp/ipadctl-platform-command/run/systemd");
    rmdir("/tmp/ipadctl-platform-command/run");
    rmdir(root);
    return 0;
}
