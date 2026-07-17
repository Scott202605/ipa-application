#ifndef MANAGER_RPC_CLIENT_H
#define MANAGER_RPC_CLIENT_H

#include <stddef.h>

int manager_rpc_call(const char *socket_path, const char *request, char *response, size_t response_size);

#endif
