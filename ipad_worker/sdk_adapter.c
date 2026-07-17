#include "sdk_adapter.h"

#include "sdk_profile_facade.h"

#include <stdio.h>
#include <string.h>

#ifdef IPAD_WORKER_ENABLE_REAL_SDK
#include "typedefs.h"
#endif

#ifdef IPAD_WORKER_HAVE_REAL_SDK
#include "ipa.h"
#include "ipa_core.h"
#endif

void sdk_adapter_init_context(sdk_adapter_t *adapter) {
    if (!adapter) {
        return;
    }
    memset(adapter, 0, sizeof(*adapter));
    adapter->mode = SDK_MODE_MOCK;
}

ipad_error_t sdk_adapter_map_errcode(int sdk_error) {
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
    switch (sdk_error) {
        case eOk: return IPAD_OK;
        case eBadArg: return IPAD_ERR_INVALID_PARAMS;
        case eNoMem: return IPAD_ERR_INTERNAL;
        case eFatal: return IPAD_ERR_SDK_FAILED;
        default: return IPAD_ERR_SDK_FAILED;
    }
#else
    switch (sdk_error) {
        case 0: return IPAD_OK;
        case 4: return IPAD_ERR_INVALID_PARAMS;
        case 9: return IPAD_ERR_INTERNAL;
        default: return IPAD_ERR_SDK_FAILED;
    }
#endif
}

ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport) {
    if (!adapter || !transport || transport[0] == '\0') {
        return IPAD_ERR_INVALID_PARAMS;
    }
    if (strcmp(transport, "real") == 0) {
#ifdef IPAD_WORKER_HAVE_REAL_SDK
        cl_config_t config = {0};
        int rc = ipa_init_library(&config, NULL);
        ipad_error_t mapped = sdk_adapter_map_errcode(rc);
        if (mapped != IPAD_OK) {
            return mapped;
        }
        adapter->mode = SDK_MODE_REAL;
        adapter->initialized = 1;
        snprintf(adapter->transport, sizeof(adapter->transport), "%s", "real");
        return IPAD_OK;
#else
        return IPAD_ERR_SDK_FAILED;
#endif
    }

    adapter->mode = SDK_MODE_MOCK;
    adapter->initialized = 1;
    snprintf(adapter->transport, sizeof(adapter->transport), "%s", transport);
    return IPAD_OK;
}

ipad_error_t sdk_adapter_deinit(sdk_adapter_t *adapter) {
    if (!adapter) {
        return IPAD_ERR_INVALID_PARAMS;
    }
#ifdef IPAD_WORKER_HAVE_REAL_SDK
    if (adapter->mode == SDK_MODE_REAL && adapter->initialized) {
        ipa_deinit_library();
    }
#endif
    adapter->initialized = 0;
    return IPAD_OK;
}

const char *sdk_adapter_mode(const sdk_adapter_t *adapter) {
    if (!adapter) {
        return "unknown";
    }
    return adapter->mode == SDK_MODE_REAL ? "real" : "mock";
}

int sdk_adapter_is_initialized(const sdk_adapter_t *adapter) {
    return adapter && adapter->initialized;
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
    if (adapter->mode == SDK_MODE_REAL) {
        fputs("real profile download requires product activation-code mapping before enabling SDK call\n", stderr);
        return IPAD_ERR_SDK_FAILED;
    }
    return IPAD_OK;
}

ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    if (!iccid || !iccid[0]) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    if (adapter->mode == SDK_MODE_REAL) {
        return sdk_profile_facade_enable(iccid);
    }
    return IPAD_OK;
}

ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    if (!iccid || !iccid[0]) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    if (adapter->mode == SDK_MODE_REAL) {
        return sdk_profile_facade_disable(iccid);
    }
    return IPAD_OK;
}

ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    if (!iccid || !iccid[0]) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    if (adapter->mode == SDK_MODE_REAL) {
        return sdk_profile_facade_delete(iccid);
    }
    return IPAD_OK;
}
