#include "support_bundle.h"

#include "config_commands.h"
#include "diagnostics.h"
#include "platform_check.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static const char *default_bundle_dir(const char *output_dir) {
    return (output_dir && output_dir[0] != '\0') ? output_dir : "/tmp/ipad-manager-support";
}

static void redact_json_string_value(char *text, const char *field) {
    char pattern[80];
    char *cursor = text;

    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    while (cursor && (cursor = strstr(cursor, pattern)) != NULL) {
        char *colon = strchr(cursor + strlen(pattern), ':');
        char *value_start;
        char *value_end;

        if (!colon) {
            break;
        }
        value_start = strchr(colon, '"');
        if (!value_start) {
            cursor = colon + 1;
            continue;
        }
        value_end = strchr(value_start + 1, '"');
        if (!value_end) {
            break;
        }
        {
            const char *redacted = "<redacted>";
            size_t value_len = (size_t)(value_end - value_start - 1);
            size_t redacted_len = strlen(redacted);

            if (value_len >= redacted_len) {
                memcpy(value_start + 1, redacted, redacted_len);
                memmove(value_start + 1 + redacted_len, value_end, strlen(value_end) + 1);
                cursor = value_start + 1 + redacted_len;
            } else {
                memset(value_start + 1, '*', value_len);
                cursor = value_end;
            }
        }
    }
}

static void redact_in_place(char *text) {
    if (!text) {
        return;
    }
    redact_json_string_value(text, "activation_code");
    redact_json_string_value(text, "token");
    redact_json_string_value(text, "password");
    redact_json_string_value(text, "secret");
}

static int ensure_dir(const char *dir) {
    if (mkdir(dir, 0700) == 0) {
        return 0;
    }
    return errno == EEXIST ? 0 : -1;
}

static int write_file(const char *path, const char *body) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    fputs(body, file);
    fclose(file);
    return 0;
}

int ipadctl_support_bundle_create(const char *config_path,
                                  const char *socket_path,
                                  const char *output_dir,
                                  char *out,
                                  size_t out_size) {
    char path[512];
    char config_show[4096];
    char config_check[4096];
    char platform[4096];
    char doctor[4096];
    const char *dir = default_bundle_dir(output_dir);

    if (!out || out_size == 0) {
        return 2;
    }
    if (ensure_dir(dir) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot create bundle directory\",\"suggestion\":\"Choose a writable --output directory\"}");
        return 1;
    }

    ipadctl_config_show_to_buffer(config_path, config_show, sizeof(config_show));
    ipadctl_config_check_to_buffer(config_path, config_check, sizeof(config_check));
    ipadctl_platform_report("/", platform, sizeof(platform));
    ipadctl_doctor(config_path, socket_path, doctor, sizeof(doctor));

    redact_in_place(config_show);
    redact_in_place(config_check);
    redact_in_place(platform);
    redact_in_place(doctor);

    snprintf(path, sizeof(path), "%s/config-show.json", dir);
    if (write_file(path, config_show) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config-show.json\"}");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/config-check.json", dir);
    if (write_file(path, config_check) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config-check.json\"}");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/platform-check.json", dir);
    if (write_file(path, platform) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write platform-check.json\"}");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/doctor.json", dir);
    if (write_file(path, doctor) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write doctor.json\"}");
        return 1;
    }

    snprintf(out, out_size,
             "{\"ok\":true,\"bundle_dir\":\"%s\",\"files\":[\"config-show.json\",\"config-check.json\",\"platform-check.json\",\"doctor.json\"],\"redacted\":true}\n",
             dir);
    redact_in_place(out);
    return 0;
}

int ipadctl_support_command(int argc, char **argv, const char *config_path, const char *socket_path) {
    const char *output_dir = NULL;
    char output[4096];
    int i;
    int rc;

    if (argc < 2 || strcmp(argv[0], "support") != 0 || strcmp(argv[1], "bundle") != 0) {
        return 2;
    }
    i = 2;
    while (i < argc) {
        if (i + 1 < argc && strcmp(argv[i], "--output") == 0) {
            output_dir = argv[i + 1];
            i += 2;
        } else {
            return 2;
        }
    }

    rc = ipadctl_support_bundle_create(config_path, socket_path, output_dir, output, sizeof(output));
    fputs(output, rc == 0 ? stdout : stderr);
    return rc;
}
