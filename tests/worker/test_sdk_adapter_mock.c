#include "sdk_adapter.h"

int main(void) {
    sdk_adapter_t adapter;

    sdk_adapter_init_context(&adapter);
    if (sdk_adapter_is_initialized(&adapter) != 0) return 1;
    if (sdk_adapter_profile_enable(&adapter, "89860123456789012345") != IPAD_ERR_SDK_NOT_INITIALIZED) return 1;
    if (sdk_adapter_init(&adapter, "mock") != IPAD_OK) return 1;
    if (sdk_adapter_is_initialized(&adapter) != 1) return 1;
    if (sdk_adapter_mode(&adapter)[0] != 'm') return 1;
    if (sdk_adapter_profile_download(&adapter, "LPA:1$smdp.example.com$ABCD") != IPAD_OK) return 1;
    if (sdk_adapter_profile_enable(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    if (sdk_adapter_profile_disable(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    if (sdk_adapter_profile_delete(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    if (sdk_adapter_deinit(&adapter) != IPAD_OK) return 1;
    if (sdk_adapter_is_initialized(&adapter) != 0) return 1;
    return 0;
}
