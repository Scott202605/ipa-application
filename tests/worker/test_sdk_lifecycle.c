#include "worker_protocol.h"

#include <string.h>

int main(void) {
    sdk_adapter_t adapter;
    char response[512];

    sdk_adapter_init_context(&adapter);

    if (worker_protocol_handle_line("{\"id\":1,\"op\":\"sdk.status\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":false")) return 1;

    if (worker_protocol_handle_line("{\"id\":2,\"op\":\"sdk.init\",\"mode\":\"mock\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":true")) return 1;

    if (worker_protocol_handle_line("{\"id\":3,\"op\":\"sdk.deinit\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":false")) return 1;
    return 0;
}
