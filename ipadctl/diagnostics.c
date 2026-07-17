#include "diagnostics.h"

#include <stdio.h>
#include <string.h>

void diagnostic_check_set(diagnostic_check_t *check, const char *name, int ok, const char *severity, const char *message, const char *suggestion) {
    if (!check) {
        return;
    }
    memset(check, 0, sizeof(*check));
    snprintf(check->name, sizeof(check->name), "%s", name ? name : "");
    check->ok = ok;
    snprintf(check->severity, sizeof(check->severity), "%s", severity ? severity : (ok ? "info" : "error"));
    snprintf(check->message, sizeof(check->message), "%s", message ? message : "");
    snprintf(check->suggestion, sizeof(check->suggestion), "%s", suggestion ? suggestion : "");
}

int diagnostic_write_check_json(const diagnostic_check_t *check, char *out, size_t out_size) {
    int written;
    if (!check || !out || out_size == 0) {
        return -1;
    }
    written = snprintf(out, out_size,
                       "{\"name\":\"%s\",\"ok\":%s,\"severity\":\"%s\",\"message\":\"%s\",\"suggestion\":\"%s\"}",
                       check->name,
                       check->ok ? "true" : "false",
                       check->severity,
                       check->message,
                       check->suggestion);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}
