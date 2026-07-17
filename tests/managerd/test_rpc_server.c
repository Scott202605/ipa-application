#include "rpc_server.h"

#include <stdio.h>
#include <string.h>

static int require_contains(const char *text, const char *needle) {
    if (!strstr(text, needle)) {
        fprintf(stderr, "missing '%s' in '%s'\n", needle, text);
        return 1;
    }
    return 0;
}

int main(void) {
    char response[512];

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "\"daemon\":\"running\"")) return 1;

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"worker.start_mock\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "\"worker\":\"ready\"")) return 1;

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"profile.download\",\"smdp\":\"smdp.example.com\",\"matching_id\":\"ABCD\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "\"state\":\"completed\"")) return 1;

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"unknown.method\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "method_not_found")) return 1;

    return 0;
}
