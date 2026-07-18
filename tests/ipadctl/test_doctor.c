#include "diagnostics.h"

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
    const char *config_path = "/tmp/ipadctl-doctor-config.json";
    const char *socket_path = "/tmp/ipadctl-missing.sock";
    const char *openrc_root = "/tmp/ipadctl-doctor-openrc";
    char out[4096];
    FILE *file;

    unlink(socket_path);
    file = fopen(config_path, "wb");
    if (!file) {
        return 1;
    }
    fputs("{\"sdk_mode\":\"mock\","
          "\"worker_path\":\"/bin/sh\","
          "\"task_store_path\":\"/tmp/ipad-manager-tasks.jsonl\","
          "\"audit_log_path\":\"/tmp/ipad-manager-audit.jsonl\","
          "\"task_retention\":8}",
          file);
    fclose(file);

    if (ipadctl_doctor(config_path, socket_path, out, sizeof(out)) != 4) return 1;
    unlink(config_path);
    if (!strstr(out, "daemon is not reachable")) return 1;
    if (!strstr(out, "systemctl restart ipad-managerd")) return 1;
    if (!strstr(out, "\"name\":\"config.check\",\"ok\":true")) return 1;
    if (!strstr(out, "\"name\":\"daemon.socket\",\"ok\":false")) return 1;

    mkdir(openrc_root, 0700);
    mkdir("/tmp/ipadctl-doctor-openrc/sbin", 0700);
    if (touch_file("/tmp/ipadctl-doctor-openrc/sbin/openrc-run") != 0) return 1;

    file = fopen(config_path, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"mock\","
          "\"worker_path\":\"/bin/sh\","
          "\"task_store_path\":\"/tmp/ipad-manager-tasks.jsonl\","
          "\"audit_log_path\":\"/tmp/ipad-manager-audit.jsonl\","
          "\"task_retention\":8}",
          file);
    fclose(file);

    if (ipadctl_doctor_with_root(config_path, socket_path, openrc_root, out, sizeof(out)) != 4) return 1;
    if (!strstr(out, "\"init\":\"openrc\"")) return 1;
    if (!strstr(out, "rc-service ipad-managerd restart")) return 1;

    unlink(config_path);
    unlink("/tmp/ipadctl-doctor-openrc/sbin/openrc-run");
    rmdir("/tmp/ipadctl-doctor-openrc/sbin");
    rmdir(openrc_root);
    return 0;
}
