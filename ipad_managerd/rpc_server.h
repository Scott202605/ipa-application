#ifndef RPC_SERVER_H
#define RPC_SERVER_H

#include <stddef.h>

int rpc_handle_request(const char *request, char *response, size_t response_size);

#endif
