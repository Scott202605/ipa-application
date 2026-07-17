#include "device_discovery.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_DEV_ROOT "/dev"

typedef struct {
    char *data;
    size_t size;
    size_t used;
} json_writer_t;

static int json_append(json_writer_t *writer, const char *fmt, ...) {
    va_list args;
    int written;

    if (!writer || !writer->data || writer->used >= writer->size) {
        return -1;
    }

    va_start(args, fmt);
    written = vsnprintf(writer->data + writer->used, writer->size - writer->used, fmt, args);
    va_end(args);

    if (written < 0 || (size_t)written >= writer->size - writer->used) {
        return -1;
    }
    writer->used += (size_t)written;
    return 0;
}

static const char *resolved_dev_root(const char *dev_root) {
    return (dev_root && dev_root[0] != '\0') ? dev_root : DEFAULT_DEV_ROOT;
}

static int has_prefix(const char *value, const char *prefix) {
    return strncmp(value, prefix, strlen(prefix)) == 0;
}

static int is_candidate_device(const char *name) {
    return has_prefix(name, "ttyUSB") || has_prefix(name, "ttyACM") || has_prefix(name, "wwan");
}

static int build_path(const char *root, const char *name, char *out, size_t out_size) {
    int written = snprintf(out, out_size, "%s/%s", root, name);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

int ipadctl_device_list(const char *dev_root, char *out, size_t out_size) {
    const char *root = resolved_dev_root(dev_root);
    DIR *dir;
    struct dirent *entry;
    int first = 1;
    int count = 0;
    json_writer_t writer = {out, out_size, 0};

    dir = opendir(root);
    if (!dir) {
        snprintf(out, out_size, "{\"ok\":false,\"dev_root\":\"%s\",\"error\":\"failed to open device directory\"}\n", root);
        return 1;
    }

    if (json_append(&writer, "{\"ok\":true,\"dev_root\":\"%s\",\"devices\":[", root) != 0) {
        closedir(dir);
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[512];
        int readable;
        int writable;

        if (!is_candidate_device(entry->d_name)) {
            continue;
        }
        if (build_path(root, entry->d_name, path, sizeof(path)) != 0) {
            closedir(dir);
            return 1;
        }

        readable = access(path, R_OK) == 0;
        writable = access(path, W_OK) == 0;
        if (json_append(&writer,
                        "%s{\"path\":\"%s\",\"readable\":%s,\"writable\":%s",
                        first ? "" : ",",
                        path,
                        readable ? "true" : "false",
                        writable ? "true" : "false") != 0) {
            closedir(dir);
            return 1;
        }
        if ((!readable || !writable) &&
            json_append(&writer, ",\"suggestion\":\"Add service user to dialout or adjust udev rules\"") != 0) {
            closedir(dir);
            return 1;
        }
        if (json_append(&writer, "}") != 0) {
            closedir(dir);
            return 1;
        }
        first = 0;
        ++count;
    }
    closedir(dir);

    if (json_append(&writer, "],\"count\":%d}\n", count) != 0) {
        return 1;
    }
    return 0;
}

int ipadctl_device_command(int argc, char **argv) {
    const char *dev_root = NULL;
    char output[4096];
    int rc;

    if (argc >= 4 && strcmp(argv[argc - 2], "--dev-root") == 0) {
        dev_root = argv[argc - 1];
        argc -= 2;
    }

    if (argc == 2 && strcmp(argv[0], "device") == 0 && strcmp(argv[1], "list") == 0) {
        rc = ipadctl_device_list(dev_root, output, sizeof(output));
        fputs(output, rc == 0 ? stdout : stderr);
        return rc;
    }
    return 2;
}
