#ifndef IPAD_CONFIG_H
#define IPAD_CONFIG_H

#include <stddef.h>

typedef struct {
    char socket_path[128];
    char worker_path[256];
    char sdk_mode[16];
    int request_timeout_ms;
    int worker_max_restarts;
    int worker_restart_window_seconds;
    char sdk_transport[32];
    char at_device[128];
    int at_baudrate;
    char sdk_log_level[16];
    char task_store_path[256];
    int task_retention;
    char audit_log_path[256];
} ipad_config_t;

void ipad_config_defaults(ipad_config_t *config);
int ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size);

#endif
