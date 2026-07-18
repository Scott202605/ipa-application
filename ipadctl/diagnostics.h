#ifndef IPADCTL_DIAGNOSTICS_H
#define IPADCTL_DIAGNOSTICS_H

#include <stddef.h>

typedef struct {
    char name[64];
    int ok;
    char severity[16];
    char message[160];
    char suggestion[200];
} diagnostic_check_t;

void diagnostic_check_set(diagnostic_check_t *check, const char *name, int ok, const char *severity, const char *message, const char *suggestion);
int diagnostic_write_check_json(const diagnostic_check_t *check, char *out, size_t out_size);
int diagnostic_write_report_json(const char *summary,
                                 const char *next_action,
                                 const diagnostic_check_t *checks,
                                 size_t check_count,
                                 char *out,
                                 size_t out_size);
int ipadctl_doctor(const char *config_path, const char *socket_path, char *out, size_t out_size);
int ipadctl_doctor_with_root(const char *config_path, const char *socket_path, const char *root, char *out, size_t out_size);

#endif
