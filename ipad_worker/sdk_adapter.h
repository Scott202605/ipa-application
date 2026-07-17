#ifndef SDK_ADAPTER_H
#define SDK_ADAPTER_H

#include "ipad_errors.h"

typedef struct {
    int initialized;
    char transport[32];
} sdk_adapter_t;

void sdk_adapter_init_context(sdk_adapter_t *adapter);
ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport);
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id);
ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid);

#endif
