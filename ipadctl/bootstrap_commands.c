#include "bootstrap_commands.h"

#include "platform_check.h"

#include <stdio.h>
#include <string.h>

static int is_real_mode(const char *mode) {
    return mode && strcmp(mode, "real") == 0;
}

static int is_mock_mode(const char *mode) {
    return mode && strcmp(mode, "mock") == 0;
}

static const char *service_profile(ipadctl_init_system_t init) {
    switch (init) {
        case IPADCTL_INIT_SYSTEMD:
            return "packaging/systemd/ipad-managerd.service";
        case IPADCTL_INIT_OPENRC:
            return "packaging/openrc/ipad-managerd";
        case IPADCTL_INIT_SYSVINIT:
            return "packaging/sysvinit/ipad-managerd";
        case IPADCTL_INIT_MANUAL:
        default:
            return "packaging/manual/README.md";
    }
}

int ipadctl_bootstrap_check(const char *root, const char *mode, const char *at_device, char *out, size_t out_size) {
    ipadctl_platform_info_t platform;
    char setup_step[256];
    int written;

    if (!out || out_size == 0) {
        return 1;
    }
    if (!is_mock_mode(mode) && !is_real_mode(mode)) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"choose --mock or --real\"}\n");
        return 2;
    }
    if (is_real_mode(mode) && (!at_device || at_device[0] == '\0')) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"missing at device\",\"suggestion\":\"Run: ipadctl device list\"}\n");
        return 2;
    }

    ipadctl_platform_detect(root, &platform);
    if (is_real_mode(mode)) {
        snprintf(setup_step, sizeof(setup_step), "Run: sudo ipadctl setup --real --at-device %s", at_device);
    } else {
        snprintf(setup_step, sizeof(setup_step), "Run: sudo ipadctl setup --mock");
    }

    written = snprintf(out, out_size,
                       "{\"ok\":true,\"mode\":\"%s\",\"init\":\"%s\",\"support\":\"%s\","
                       "\"steps\":["
                       "\"%s\","
                       "\"Install or adapt %s\","
                       "\"%s\","
                       "\"Run: ipadctl doctor\""
                       "],\"next_action\":\"%s\"}\n",
                       mode,
                       ipadctl_init_system_name(platform.init_system),
                       ipadctl_support_level_name(platform.support),
                       setup_step,
                       service_profile(platform.init_system),
                       ipadctl_restart_hint(platform.init_system),
                       setup_step);
    return written > 0 && (size_t)written < out_size ? 0 : 1;
}

int ipadctl_bootstrap_command(int argc, char **argv) {
    const char *root = NULL;
    const char *mode = NULL;
    const char *at_device = NULL;
    char output[4096];
    int i;
    int rc;

    if (argc < 2 || strcmp(argv[0], "bootstrap") != 0 || strcmp(argv[1], "check") != 0) {
        return 2;
    }

    for (i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--mock") == 0) {
            mode = "mock";
        } else if (strcmp(argv[i], "--real") == 0) {
            mode = "real";
        } else if (strcmp(argv[i], "--at-device") == 0 && i + 1 < argc) {
            at_device = argv[++i];
        } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
            root = argv[++i];
        } else {
            return 2;
        }
    }

    rc = ipadctl_bootstrap_check(root, mode, at_device, output, sizeof(output));
    fputs(output, rc == 0 ? stdout : stderr);
    return rc;
}
