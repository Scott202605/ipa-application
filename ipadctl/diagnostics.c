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
