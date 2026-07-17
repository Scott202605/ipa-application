#include "sdk_adapter.h"

#include <stdio.h>

int main(void) {
    sdk_adapter_t adapter;

    sdk_adapter_init_context(&adapter);
    if (sdk_adapter_init(&adapter, "at_serial") != IPAD_OK) {
        fputs("{\"event\":\"worker.error\",\"error\":\"sdk_init_failed\"}\n", stderr);
        return 1;
    }
    puts("{\"event\":\"worker.ready\"}");
    return 0;
}
