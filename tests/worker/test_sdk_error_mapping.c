#include "sdk_adapter.h"

int main(void) {
    if (sdk_adapter_map_errcode(0) != IPAD_OK) return 1;
    if (sdk_adapter_map_errcode(4) != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_adapter_map_errcode(1) != IPAD_ERR_SDK_FAILED) return 1;
    return 0;
}
