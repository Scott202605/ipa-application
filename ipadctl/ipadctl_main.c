#include "bootstrap_commands.h"
#include "config_commands.h"
#include "device_discovery.h"
#include "diagnostics.h"
#include "ipad_protocol.h"
#include "ipad_socket.h"
#include "platform_check.h"
#include "setup_commands.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *argv0) {
    printf("Usage:\n");
    printf("  %s [--config <path>] config show\n", argv0);
    printf("  %s [--config <path>] config check\n", argv0);
    printf("  %s device list [--dev-root <path>]\n", argv0);
    printf("  %s [--config <path>] setup --mock\n", argv0);
    printf("  %s [--config <path>] setup --real --at-device <path>\n", argv0);
    printf("  %s bootstrap check --mock\n", argv0);
    printf("  %s bootstrap check --real --at-device <path>\n", argv0);
    printf("  %s platform check\n", argv0);
    printf("  %s [--config <path>] [--socket <path>] doctor\n", argv0);
    printf("  %s [--socket <path>] status\n", argv0);
    printf("  %s [--socket <path>] sdk init\n", argv0);
    printf("  %s [--socket <path>] sdk status\n", argv0);
    printf("  %s [--socket <path>] sdk deinit\n", argv0);
    printf("  %s [--socket <path>] task get <task-id>\n", argv0);
    printf("  %s [--socket <path>] profile download --activation-code <code>\n", argv0);
    printf("  %s [--socket <path>] profile download --smdp <fqdn> --matching-id <id>\n", argv0);
    printf("  %s [--socket <path>] profile enable --iccid <iccid>\n", argv0);
    printf("  %s [--socket <path>] profile disable --iccid <iccid>\n", argv0);
    printf("  %s [--socket <path>] profile delete --iccid <iccid>\n", argv0);
}

static int send_request(const char *socket_path, const char *request) {
    int fd;
    char response[IPAD_MAX_JSON_MESSAGE];

    fd = ipad_socket_connect(socket_path);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to %s\n", socket_path);
        return 1;
    }
    if (ipad_socket_write_line(fd, request) != 0 ||
        ipad_socket_read_line(fd, response, sizeof(response)) != 0) {
        fprintf(stderr, "failed to exchange request with daemon\n");
        ipad_socket_close(fd);
        return 1;
    }
    ipad_socket_close(fd);
    fputs(response, stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char *socket_path = IPAD_DEFAULT_SOCKET_PATH;
    const char *config_path = NULL;
    int argi = 1;
    char request[IPAD_MAX_JSON_MESSAGE];

    while (argc - argi >= 2) {
        if (strcmp(argv[argi], "--socket") == 0) {
            socket_path = argv[argi + 1];
            argi += 2;
        } else if (strcmp(argv[argi], "--config") == 0) {
            config_path = argv[argi + 1];
            argi += 2;
        } else {
            break;
        }
    }

    if (argc - argi >= 1 && strcmp(argv[argi], "config") == 0) {
        int rc = ipadctl_config_command(argc - argi, argv + argi, config_path);
        if (rc != 2) {
            return rc;
        }
    }
    if (argc - argi >= 1 && strcmp(argv[argi], "device") == 0) {
        int rc = ipadctl_device_command(argc - argi, argv + argi);
        if (rc != 2) {
            return rc;
        }
    }
    if (argc - argi >= 1 && strcmp(argv[argi], "setup") == 0) {
        int rc = ipadctl_setup_command(argc - argi, argv + argi, config_path);
        if (rc != 2) {
            return rc;
        }
    }
    if (argc - argi >= 1 && strcmp(argv[argi], "bootstrap") == 0) {
        int rc = ipadctl_bootstrap_command(argc - argi, argv + argi);
        if (rc != 2) {
            return rc;
        }
    }
    if (argc - argi >= 1 && strcmp(argv[argi], "platform") == 0) {
        int rc = ipadctl_platform_command(argc - argi, argv + argi);
        if (rc != 2) {
            return rc;
        }
    }
    if (argc - argi == 1 && strcmp(argv[argi], "doctor") == 0) {
        char output[4096];
        int rc = ipadctl_doctor(config_path, socket_path, output, sizeof(output));
        fputs(output, rc == 0 ? stdout : stderr);
        return rc;
    }

    if (argc - argi == 1 && strcmp(argv[argi], "status") == 0) {
        snprintf(request, sizeof(request),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\"}",
                 IPAD_METHOD_SYSTEM_STATUS);
        return send_request(socket_path, request);
    }
    if (argc - argi == 2 && strcmp(argv[argi], "sdk") == 0) {
        const char *sub = argv[argi + 1];
        const char *method = NULL;

        if (strcmp(sub, "init") == 0) {
            method = IPAD_METHOD_SDK_INIT;
        } else if (strcmp(sub, "status") == 0) {
            method = IPAD_METHOD_SDK_STATUS;
        } else if (strcmp(sub, "deinit") == 0) {
            method = IPAD_METHOD_SDK_DEINIT;
        }
        if (method) {
            snprintf(request, sizeof(request),
                     "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\"}",
                     method);
            return send_request(socket_path, request);
        }
    }
    if (argc - argi == 3 && strcmp(argv[argi], "task") == 0 && strcmp(argv[argi + 1], "get") == 0) {
        snprintf(request, sizeof(request),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"task_id\":\"%s\"}",
                 IPAD_METHOD_TASK_GET,
                 argv[argi + 2]);
        return send_request(socket_path, request);
    }
    if (argc - argi == 6 &&
        strcmp(argv[argi], "profile") == 0 &&
        strcmp(argv[argi + 1], "download") == 0 &&
        strcmp(argv[argi + 2], "--smdp") == 0 &&
        strcmp(argv[argi + 4], "--matching-id") == 0) {
        snprintf(request, sizeof(request),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"activation_code\":\"LPA:1$%s$%s\"}",
                 IPAD_METHOD_PROFILE_DOWNLOAD,
                 argv[argi + 3],
                 argv[argi + 5]);
        return send_request(socket_path, request);
    }
    if (argc - argi == 4 &&
        strcmp(argv[argi], "profile") == 0 &&
        strcmp(argv[argi + 1], "download") == 0 &&
        strcmp(argv[argi + 2], "--activation-code") == 0) {
        snprintf(request, sizeof(request),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"activation_code\":\"%s\"}",
                 IPAD_METHOD_PROFILE_DOWNLOAD,
                 argv[argi + 3]);
        return send_request(socket_path, request);
    }
    if (argc - argi == 4 &&
        strcmp(argv[argi], "profile") == 0 &&
        strcmp(argv[argi + 2], "--iccid") == 0) {
        const char *method = NULL;

        if (strcmp(argv[argi + 1], "enable") == 0) {
            method = IPAD_METHOD_PROFILE_ENABLE;
        } else if (strcmp(argv[argi + 1], "disable") == 0) {
            method = IPAD_METHOD_PROFILE_DISABLE;
        } else if (strcmp(argv[argi + 1], "delete") == 0) {
            method = IPAD_METHOD_PROFILE_DELETE;
        }
        if (method) {
            snprintf(request, sizeof(request),
                     "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"iccid\":\"%s\"}",
                     method,
                     argv[argi + 3]);
            return send_request(socket_path, request);
        }
    }

    usage(argv[0]);
    return 2;
}
