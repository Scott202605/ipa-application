#include "platform_check.h"

#include "diagnostics.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static const char *root_path(const char *root) {
    return (root && root[0] != '\0') ? root : "/";
}

static int join_root_path(const char *root, const char *suffix, char *out, size_t out_size) {
    const char *base = root_path(root);
    int written;

    if (strcmp(base, "/") == 0) {
        written = snprintf(out, out_size, "%s", suffix);
    } else {
        written = snprintf(out, out_size, "%s%s", base, suffix);
    }
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

static int path_exists(const char *root, const char *suffix) {
    char path[512];
    struct stat st;

    if (join_root_path(root, suffix, path, sizeof(path)) != 0) {
        return 0;
    }
    return stat(path, &st) == 0;
}

static void detect_libc(char *out, size_t out_size) {
#if defined(__GLIBC__)
    snprintf(out, out_size, "glibc");
#elif defined(__MUSL__)
    snprintf(out, out_size, "musl");
#else
    snprintf(out, out_size, "unknown");
#endif
}

static ipadctl_init_system_t detect_init_system(const char *root) {
    if (path_exists(root, "/run/systemd/system")) {
        return IPADCTL_INIT_SYSTEMD;
    }
    if (path_exists(root, "/sbin/openrc-run")) {
        return IPADCTL_INIT_OPENRC;
    }
    if (path_exists(root, "/etc/init.d")) {
        return IPADCTL_INIT_SYSVINIT;
    }
    return IPADCTL_INIT_MANUAL;
}

static ipadctl_support_level_t classify_support(const ipadctl_platform_info_t *info) {
    if (!info || strcmp(info->sysname, "Linux") != 0) {
        return IPADCTL_SUPPORT_UNSUPPORTED;
    }
    if (info->init_system == IPADCTL_INIT_SYSTEMD) {
        return IPADCTL_SUPPORT_SUPPORTED;
    }
    return IPADCTL_SUPPORT_DEGRADED;
}

void ipadctl_platform_detect(const char *root, ipadctl_platform_info_t *info) {
    struct utsname uts;

    if (!info) {
        return;
    }
    memset(info, 0, sizeof(*info));

    if (uname(&uts) == 0) {
        snprintf(info->sysname, sizeof(info->sysname), "%s", uts.sysname);
        snprintf(info->release, sizeof(info->release), "%s", uts.release);
        snprintf(info->machine, sizeof(info->machine), "%s", uts.machine);
    } else {
        snprintf(info->sysname, sizeof(info->sysname), "unknown");
        snprintf(info->release, sizeof(info->release), "unknown");
        snprintf(info->machine, sizeof(info->machine), "unknown");
    }

    detect_libc(info->libc, sizeof(info->libc));
    info->init_system = detect_init_system(root);
    info->has_run_dir = path_exists(root, "/run");
    info->has_tmp_dir = path_exists(root, "/tmp") || strcmp(root_path(root), "/") != 0;
    info->support = classify_support(info);
}

const char *ipadctl_init_system_name(ipadctl_init_system_t init) {
    switch (init) {
        case IPADCTL_INIT_SYSTEMD:
            return "systemd";
        case IPADCTL_INIT_OPENRC:
            return "openrc";
        case IPADCTL_INIT_SYSVINIT:
            return "sysvinit";
        case IPADCTL_INIT_MANUAL:
        default:
            return "manual";
    }
}

const char *ipadctl_support_level_name(ipadctl_support_level_t support) {
    switch (support) {
        case IPADCTL_SUPPORT_SUPPORTED:
            return "supported";
        case IPADCTL_SUPPORT_DEGRADED:
            return "degraded";
        case IPADCTL_SUPPORT_UNSUPPORTED:
        default:
            return "unsupported";
    }
}

const char *ipadctl_restart_hint(ipadctl_init_system_t init) {
    switch (init) {
        case IPADCTL_INIT_SYSTEMD:
            return "Run: sudo systemctl restart ipad-managerd";
        case IPADCTL_INIT_OPENRC:
            return "Run: sudo rc-service ipad-managerd restart after installing packaging/openrc/ipad-managerd";
        case IPADCTL_INIT_SYSVINIT:
            return "Run: sudo service ipad-managerd restart after installing packaging/sysvinit/ipad-managerd";
        case IPADCTL_INIT_MANUAL:
        default:
            return "Run: ipad-managerd under your supervisor, then run ipadctl doctor";
    }
}

int ipadctl_platform_report(const char *root, char *out, size_t out_size) {
    ipadctl_platform_info_t info;
    diagnostic_check_t arch_check;
    diagnostic_check_t init_check;
    char arch_json[640];
    char init_json[640];
    int ok;
    int written;

    if (!out || out_size == 0) {
        return 1;
    }

    ipadctl_platform_detect(root, &info);
    ok = info.support != IPADCTL_SUPPORT_UNSUPPORTED;
    diagnostic_check_set(&arch_check,
                         "platform.arch",
                         strcmp(info.machine, "unknown") != 0,
                         "info",
                         info.machine,
                         "");
    diagnostic_check_set(&init_check,
                         "platform.init",
                         info.init_system == IPADCTL_INIT_SYSTEMD,
                         info.init_system == IPADCTL_INIT_SYSTEMD ? "info" : "warning",
                         ipadctl_init_system_name(info.init_system),
                         info.init_system == IPADCTL_INIT_SYSTEMD ? "" : "Use the matching packaging profile or manual supervisor guidance");

    if (diagnostic_write_check_json(&arch_check, arch_json, sizeof(arch_json)) != 0 ||
        diagnostic_write_check_json(&init_check, init_json, sizeof(init_json)) != 0) {
        return 1;
    }

    written = snprintf(out, out_size,
                       "{\"ok\":%s,\"support\":\"%s\",\"platform\":{"
                       "\"sysname\":\"%s\","
                       "\"release\":\"%s\","
                       "\"machine\":\"%s\","
                       "\"libc\":\"%s\","
                       "\"init\":\"%s\","
                       "\"has_run_dir\":%s,"
                       "\"has_tmp_dir\":%s"
                       "},\"checks\":[%s,%s],\"next_action\":\"Run: ipadctl doctor\"}\n",
                       ok ? "true" : "false",
                       ipadctl_support_level_name(info.support),
                       info.sysname,
                       info.release,
                       info.machine,
                       info.libc,
                       ipadctl_init_system_name(info.init_system),
                       info.has_run_dir ? "true" : "false",
                       info.has_tmp_dir ? "true" : "false",
                       arch_json,
                       init_json);
    return written > 0 && (size_t)written < out_size ? 0 : 1;
}
