#include "diagnostics.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *config_path = "/tmp/ipadctl-doctor-config.json";
    const char *socket_path = "/tmp/ipadctl-missing.sock";
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
    return 0;
}
