#include "rpc_server.h"

#include <stdio.h>

int main(int argc, char **argv) {
    char response[512];

    (void)argc;
    (void)argv;

    rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}", response, sizeof(response));
    fputs(response, stdout);
    return 0;
}
