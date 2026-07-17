#include "sdk_adapter.h"

#include <stdio.h>
#include <string.h>

void sdk_adapter_init_context(sdk_adapter_t *adapter) {
    if (!adapter) {
        return;
    }
    memset(adapter, 0, sizeof(*adapter));
}

ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport) {
    if (!adapter || !transport || transport[0] == '\0') {
        return IPAD_ERR_INVALID_PARAMS;
    }
    adapter->initialized = 1;
    snprintf(adapter->transport, sizeof(adapter->transport), "%s", transport);
    return IPAD_OK;
}

static ipad_error_t require_ready(sdk_adapter_t *adapter) {
    return adapter && adapter->initialized ? IPAD_OK : IPAD_ERR_SDK_NOT_INITIALIZED;
}

ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    if (!smdp || smdp[0] == '\0' || !matching_id || matching_id[0] == '\0') {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return IPAD_OK;
}

ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}
