#ifndef IPADCTL_PLATFORM_CHECK_H
#define IPADCTL_PLATFORM_CHECK_H

#include <stddef.h>

typedef enum {
    IPADCTL_INIT_SYSTEMD = 0,
    IPADCTL_INIT_OPENRC,
    IPADCTL_INIT_SYSVINIT,
    IPADCTL_INIT_MANUAL
} ipadctl_init_system_t;

typedef enum {
    IPADCTL_SUPPORT_SUPPORTED = 0,
    IPADCTL_SUPPORT_DEGRADED,
    IPADCTL_SUPPORT_UNSUPPORTED
} ipadctl_support_level_t;

typedef struct {
    char sysname[128];
    char release[128];
    char machine[128];
    char libc[32];
    ipadctl_init_system_t init_system;
    ipadctl_support_level_t support;
    int has_run_dir;
    int has_tmp_dir;
} ipadctl_platform_info_t;

void ipadctl_platform_detect(const char *root, ipadctl_platform_info_t *info);
const char *ipadctl_init_system_name(ipadctl_init_system_t init);
const char *ipadctl_support_level_name(ipadctl_support_level_t support);
const char *ipadctl_restart_hint(ipadctl_init_system_t init);
int ipadctl_platform_report(const char *root, char *out, size_t out_size);
int ipadctl_platform_command(int argc, char **argv);

#endif
