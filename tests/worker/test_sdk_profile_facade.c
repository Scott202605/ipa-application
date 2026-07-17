#include "sdk_profile_facade.h"

int main(void) {
    if (sdk_profile_facade_enable("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_disable("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_delete("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_enable("89860123456789012345") != IPAD_ERR_SDK_FAILED) return 1;
    return 0;
}
