#ifdef ENABLE_MOCK_RESPONSE

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "ipa.h"

// 模拟响应配置
typedef struct {
    bool mock_enabled;
    ErrCode mock_error_code;
    void *mock_response_data;
    size_t mock_response_size;
} debug_config_t;

static debug_config_t g_debug_config = {
    .mock_enabled = false,
    .mock_error_code = eOk,
    .mock_response_data = NULL,
    .mock_response_size = 0
};

// 设置模拟响应
int mock_set_response(ErrCode error_code, const void *data, size_t size) {
    g_debug_config.mock_enabled = true;
    g_debug_config.mock_error_code = error_code;
    
    if (data && size > 0) {
        // 复制数据
        if (g_debug_config.mock_response_data) {
            free(g_debug_config.mock_response_data);
        }
        g_debug_config.mock_response_data = malloc(size);
        if (g_debug_config.mock_response_data) {
            memcpy(g_debug_config.mock_response_data, data, size);
            g_debug_config.mock_response_size = size;
        }
    }
    
    return 0;
}

// 清除模拟响应
void mock_clear_response(void) {
    g_debug_config.mock_enabled = false;
    g_debug_config.mock_error_code = eOk;
    
    if (g_debug_config.mock_response_data) {
        free(g_debug_config.mock_response_data);
        g_debug_config.mock_response_data = NULL;
        g_debug_config.mock_response_size = 0;
    }
}

// 是否处于模拟模式
bool mock_is_enabled(void) {
    return g_debug_config.mock_enabled;
}

// 获取模拟错误码
ErrCode mock_get_error_code(void) {
    return g_debug_config.mock_error_code;
}

// 获取模拟响应数据
const void* mock_get_response_data(size_t *out_size) {
    if (out_size) {
        *out_size = g_debug_config.mock_response_size;
    }
    return g_debug_config.mock_response_data;
}

#endif // ENABLE_MOCK_RESPONSE
