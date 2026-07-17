#include "worker_protocol.h"

#include "ipad_protocol.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    sdk_adapter_t adapter;
    const char *sdk_mode = "mock";
    char request[IPAD_MAX_JSON_MESSAGE];
    char response[IPAD_MAX_JSON_MESSAGE];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sdk-mode") == 0 && i + 1 < argc) {
            sdk_mode = argv[++i];
        } else {
            fprintf(stderr, "Usage: %s [--sdk-mode mock|real]\n", argv[0]);
            return 2;
        }
    }

    sdk_adapter_init_context(&adapter);
    if (sdk_adapter_init(&adapter, sdk_mode) != IPAD_OK) {
        fputs("{\"event\":\"worker.error\",\"error\":\"sdk_init_failed\"}\n", stderr);
        return 1;
    }

    printf("{\"event\":\"worker.ready\",\"protocol\":1,\"sdk_mode\":\"%s\"}\n", sdk_mode);
    fflush(stdout);

    while (fgets(request, sizeof(request), stdin)) {
        if (worker_protocol_handle_line(request, response, sizeof(response), &adapter) != 0) {
            fputs("{\"id\":0,\"ok\":false,\"error\":\"internal_error\"}\n", stdout);
        } else {
            fputs(response, stdout);
        }
        fflush(stdout);
    }

    sdk_adapter_deinit(&adapter);
    return 0;
}
