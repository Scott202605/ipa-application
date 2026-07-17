#include "ipad_protocol.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *argv0) {
    printf("Usage:\n");
    printf("  %s status\n", argv0);
    printf("  %s profile download --smdp <fqdn> --matching-id <id>\n", argv0);
    printf("  %s profile enable --iccid <iccid>\n", argv0);
    printf("  %s profile disable --iccid <iccid>\n", argv0);
    printf("  %s profile delete --iccid <iccid>\n", argv0);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        puts("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" IPAD_METHOD_SYSTEM_STATUS "\"}");
        return 0;
    }
    if (argc == 7 &&
        strcmp(argv[1], "profile") == 0 &&
        strcmp(argv[2], "download") == 0 &&
        strcmp(argv[3], "--smdp") == 0 &&
        strcmp(argv[5], "--matching-id") == 0) {
        printf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" IPAD_METHOD_PROFILE_DOWNLOAD "\",\"smdp\":\"%s\",\"matching_id\":\"%s\"}\n",
               argv[4],
               argv[6]);
        return 0;
    }
    if (argc == 5 &&
        strcmp(argv[1], "profile") == 0 &&
        strcmp(argv[3], "--iccid") == 0) {
        const char *method = NULL;

        if (strcmp(argv[2], "enable") == 0) {
            method = IPAD_METHOD_PROFILE_ENABLE;
        } else if (strcmp(argv[2], "disable") == 0) {
            method = IPAD_METHOD_PROFILE_DISABLE;
        } else if (strcmp(argv[2], "delete") == 0) {
            method = IPAD_METHOD_PROFILE_DELETE;
        }
        if (method) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"iccid\":\"%s\"}\n",
                   method,
                   argv[4]);
            return 0;
        }
    }

    usage(argv[0]);
    return 2;
}
