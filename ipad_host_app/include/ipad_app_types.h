#ifndef IPAD_APP_TYPES_H
#define IPAD_APP_TYPES_H

#include <stdint.h>
#include <stdbool.h>

// 支持的功能模块
typedef enum {
    API_CATEGORY_INIT = 0,        // 初始化类
    API_CATEGORY_PROFILE,         // Profile 管理
    API_CATEGORY_SESSION,         // 会话管理  
    API_CATEGORY_NOTIFICATION,    // 通知处理
    API_CATEGORY_FALLBACK,        // Fallback 机制
    API_CATEGORY_EMERGENCY,       // 应急功能
    API_CATEGORY_INFO,            // 信息获取
    API_CATEGORY_DEBUG            // 调试功能
} api_category_t;

// API 描述结构
typedef struct {
    const char *name;             // API 名称
    const char *display_name;     // 显示名称
    api_category_t category;      // 所属分类
    const char *description;      // 功能描述
} api_descriptor_t;

// 参数类型
typedef enum {
    PARAM_TYPE_STRING = 0,        // 字符串
    PARAM_TYPE_INT,               // 整数
    PARAM_TYPE_UINT,              // 无符号整数
    PARAM_TYPE_BOOL,              // 布尔值
    PARAM_TYPE_ENUM,              // 枚举（下拉选择）
    PARAM_TYPE_HEX,               // 十六进制
    PARAM_TYPE_FILE               // 文件路径
} param_type_t;

// 参数定义
typedef struct {
    const char *name;             // 参数名
    const char *display_name;     // 显示名称
    param_type_t type;            // 参数类型
    const char **enum_values;     // 枚举值列表（如果是 ENUM 类型）
    int enum_count;               // 枚举值数量
    const char *default_value;    // 默认值
    bool required;                // 是否必填
    const char *description;      // 参数描述
} param_descriptor_t;

// API 参数列表（以 NULL 结尾）
typedef struct {
    const param_descriptor_t *params;
    int count;
} api_param_list_t;

#endif // IPAD_APP_TYPES_H
