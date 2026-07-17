#include "worker_protocol.h"

#include <string.h>

int main(void) {
    sdk_adapter_t adapter;
    char response[512];

    sdk_adapter_init_context(&adapter);
    if (sdk_adapter_init(&adapter, "mock") != IPAD_OK) return 1;
    if (worker_protocol_handle_line("{\"id\":1,\"op\":\"profile.download\",\"task_id\":\"task-1\",\"activation_code\":\"LPA:1$smdp.example.com$ABCD\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"ok\":true")) return 1;
    if (worker_protocol_handle_line("{\"id\":4,\"op\":\"profile.download\",\"task_id\":\"task-4\",\"smdp\":\"smdp.example.com\",\"matching_id\":\"ABCD\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"ok\":true")) return 1;
    if (worker_protocol_handle_line("{\"id\":2,\"op\":\"profile.delete\",\"task_id\":\"task-2\",\"iccid\":\"\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"ok\":false")) return 1;
    return 0;
}
