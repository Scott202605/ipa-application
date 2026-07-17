#include "manager_rpc_client.h"

#include <stdio.h>

int manager_rpc_call(const char *socket_path, const char *request, char *response, size_t response_size) {
    (void)socket_path;
    (void)request;

    if (!response || response_size == 0) {
        return -1;
    }
    snprintf(response, response_size, "{\"jsonrpc\":\"2.0\",\"result\":{\"daemon\":\"unavailable_offline\"}}\n");
    return 0;
}
