#include "support_bundle.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *config = "/tmp/ipadctl-support-config.json";
    const char *out_dir = "/tmp/ipadctl-support-bundle";
    char out[2048];
    FILE *file = fopen(config, "wb");

    if (!file) return 1;
    fputs("{\"sdk_mode\":\"mock\",\"worker_path\":\"/bin/sh\",\"activation_code\":\"LPA:1$secret.example$TOKEN\"}", file);
    fclose(file);

    if (ipadctl_support_bundle_create(config, "/tmp/missing-ipad.sock", out_dir, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"ok\":true")) return 1;
    if (strstr(out, "TOKEN")) return 1;
    unlink(config);
    return 0;
}
