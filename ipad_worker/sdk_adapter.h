#ifndef SDK_ADAPTER_H
#define SDK_ADAPTER_H

#include <stddef.h>

#include "ipad_errors.h"

typedef enum {
    SDK_MODE_MOCK = 0,
    SDK_MODE_REAL = 1
} sdk_mode_t;

typedef struct {
    int initialized;
    sdk_mode_t mode;
    char transport[32];
} sdk_adapter_t;

void sdk_adapter_init_context(sdk_adapter_t *adapter);
ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport);
ipad_error_t sdk_adapter_deinit(sdk_adapter_t *adapter);
const char *sdk_adapter_mode(const sdk_adapter_t *adapter);
int sdk_adapter_is_initialized(const sdk_adapter_t *adapter);
ipad_error_t sdk_adapter_sdk_status(const sdk_adapter_t *adapter, char *out_json, size_t out_size);
ipad_error_t sdk_adapter_map_errcode(int sdk_error);
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id);
ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid);

#endif
