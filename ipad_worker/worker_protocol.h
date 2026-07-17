#ifndef WORKER_PROTOCOL_H
#define WORKER_PROTOCOL_H

#include <stddef.h>
#include "sdk_adapter.h"

int worker_protocol_handle_line(const char *request, char *response, size_t response_size, sdk_adapter_t *adapter);

#endif
