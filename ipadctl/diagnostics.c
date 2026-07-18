#include "diagnostics.h"

#include "config_commands.h"
#include "ipad_protocol.h"
#include "ipad_socket.h"
#include "platform_check.h"

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

static int append_text(char *out, size_t out_size, size_t *used, const char *text) {
    int written;

    if (!out || !used || !text || *used >= out_size) {
        return -1;
    }
    written = snprintf(out + *used, out_size - *used, "%s", text);
    if (written <= 0 || (size_t)written >= out_size - *used) {
        return -1;
    }
    *used += (size_t)written;
    return 0;
}

int diagnostic_write_report_json(const char *summary,
                                 const char *next_action,
                                 const diagnostic_check_t *checks,
                                 size_t check_count,
                                 char *out,
                                 size_t out_size) {
    size_t used = 0;
    size_t i;
    int ok = 1;
    int written;

    if (!out || out_size == 0 || (check_count > 0 && !checks)) {
        return -1;
    }
    for (i = 0; i < check_count; ++i) {
        if (!checks[i].ok && strcmp(checks[i].severity, "warning") != 0) {
            ok = 0;
        }
    }

    written = snprintf(out, out_size,
                       "{\"ok\":%s,\"summary\":\"%s\",\"next_action\":\"%s\",\"checks\":[",
                       ok ? "true" : "false",
                       summary ? summary : "",
                       next_action ? next_action : "");
    if (written <= 0 || (size_t)written >= out_size) {
        return -1;
    }
    used = (size_t)written;

    for (i = 0; i < check_count; ++i) {
        char check_json[512];
        if (diagnostic_write_check_json(&checks[i], check_json, sizeof(check_json)) != 0) {
            return -1;
        }
        if (i > 0 && append_text(out, out_size, &used, ",") != 0) {
            return -1;
        }
        if (append_text(out, out_size, &used, check_json) != 0) {
            return -1;
        }
    }
    if (append_text(out, out_size, &used, "]}") != 0) {
        return -1;
    }
    return 0;
}

int ipadctl_doctor_with_root(const char *config_path, const char *socket_path, const char *root, char *out, size_t out_size) {
    char config_json[IPAD_MAX_JSON_MESSAGE];
    ipadctl_platform_info_t platform;
    const char *path = (socket_path && socket_path[0] != '\0') ? socket_path : IPAD_DEFAULT_SOCKET_PATH;
    int config_rc = ipadctl_config_check_to_buffer(config_path, config_json, sizeof(config_json));
    int fd = ipad_socket_connect(path);

    ipadctl_platform_detect(root, &platform);

    if (fd < 0) {
        snprintf(out, out_size,
                 "{\"ok\":false,\"summary\":\"daemon is not reachable\","
                 "\"next_action\":\"%s\","
                 "\"platform\":{\"init\":\"%s\",\"support\":\"%s\"},"
                 "\"checks\":["
                 "{\"name\":\"config.check\",\"ok\":%s},"
                 "{\"name\":\"platform.init\",\"ok\":%s,\"severity\":\"%s\",\"message\":\"%s\"},"
                 "{\"name\":\"daemon.socket\",\"ok\":false,\"severity\":\"error\","
                 "\"message\":\"cannot connect to %s\","
                 "\"suggestion\":\"Start ipad-managerd or check socket_path\"}"
                 "]}\n",
                 ipadctl_restart_hint(platform.init_system),
                 ipadctl_init_system_name(platform.init_system),
                 ipadctl_support_level_name(platform.support),
                 config_rc == 0 ? "true" : "false",
                 platform.init_system == IPADCTL_INIT_SYSTEMD ? "true" : "false",
                 platform.init_system == IPADCTL_INIT_SYSTEMD ? "info" : "warning",
                 ipadctl_init_system_name(platform.init_system),
                 path);
        return 4;
    }

    ipad_socket_close(fd);
    snprintf(out, out_size,
             "{\"ok\":%s,\"summary\":\"daemon socket is reachable\","
             "\"next_action\":\"Run: ipadctl status\","
             "\"platform\":{\"init\":\"%s\",\"support\":\"%s\"},"
             "\"checks\":["
             "{\"name\":\"config.check\",\"ok\":%s},"
             "{\"name\":\"daemon.socket\",\"ok\":true,\"severity\":\"info\",\"message\":\"connected\"}"
             "]}\n",
             config_rc == 0 ? "true" : "false",
             ipadctl_init_system_name(platform.init_system),
             ipadctl_support_level_name(platform.support),
             config_rc == 0 ? "true" : "false");
    return config_rc == 0 ? 0 : 1;
}

int ipadctl_doctor(const char *config_path, const char *socket_path, char *out, size_t out_size) {
    return ipadctl_doctor_with_root(config_path, socket_path, "/", out, out_size);
}
