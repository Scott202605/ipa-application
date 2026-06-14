#ifndef APP_API_DEFINITIONS_H
#define APP_API_DEFINITIONS_H

#include "ipad_app_types.h"

// ============================================================================
// API 列表（按分类）
// ============================================================================

// 初始化类 API
static const api_descriptor_t API_INIT[] = {
    {"ipa__return_from_fallback", "从 Fallback 返回", API_CATEGORY_INIT, 
     "从 Fallback Profile 返回到正常 Profile"},
    {"ipa__execute_fallback_mechanism", "执行 Fallback 机制", API_CATEGORY_INIT,
     "触发 Fallback Profile 机制"},
    {NULL, NULL, API_CATEGORY_INIT, NULL}
};

// 信息获取类 API
static const api_descriptor_t API_INFO[] = {
    {"ipa__get_certs", "获取证书信息", API_CATEGORY_INFO,
     "获取 eUICC 证书（EUM 和 eUICC 证书）"},
    {"ipa__get_all_profiles_info", "获取所有 Profile 信息", API_CATEGORY_INFO,
     "获取已安装的所有 Profile 信息"},
    {"ipa__get_eim_configuration", "获取 eIM 配置", API_CATEGORY_INFO,
     "获取 eIM 配置信息"},
    {"ipa__get_euicc_info_1", "获取 euiccInfo1", API_CATEGORY_INFO,
     "获取 eUICC 基本信息（识别、能力、安全信息）"},
    {"ipa__get_euicc_info_2", "获取 euiccInfo2", API_CATEGORY_INFO,
     "获取 eUICC 详细信息（能力、版本、证书）"},
    {"ipa__get_eid_cstring", "获取 EID", API_CATEGORY_INFO,
     "获取 eUICC EID（十六进制字符串）"},
    {NULL, NULL, API_CATEGORY_INFO, NULL}
};

// Profile 管理 API
static const api_descriptor_t API_PROFILE[] = {
    {"ipad_wrapper_profile_download", "下载 Profile", API_CATEGORY_PROFILE,
     "从 SM-DP+ 下载 Profile（当前为框架代码）"},
    {"ipad_wrapper_profile_enable", "启用 Profile", API_CATEGORY_PROFILE,
     "按 ICCID 启用 Profile（当前为框架代码）"},
    {"ipad_wrapper_profile_disable", "禁用 Profile", API_CATEGORY_PROFILE,
     "按 ICCID 禁用 Profile（当前为框架代码）"},
    {"ipad_wrapper_profile_delete", "删除 Profile", API_CATEGORY_PROFILE,
     "按 ICCID 删除 Profile（当前为框架代码）"},
    {NULL, NULL, API_CATEGORY_PROFILE, NULL}
};

// 会话管理 API
static const api_descriptor_t API_SESSION[] = {
    {"ipad_wrapper_connect_mqtt", "连接 MQTT 服务", API_CATEGORY_SESSION,
     "连接 MQTT EIM 服务"},
    {"ipad_wrapper_connect_lwm2m", "连接 LwM2M 服务", API_CATEGORY_SESSION,
     "连接 LwM2M EIM 服务"},
    {"ipad_wrapper_connect_http", "连接 HTTP 服务", API_CATEGORY_SESSION,
     "连接 HTTP EIM 服务"},
    {"ipad_wrapper_stop_eim_service", "停止 EIM 服务", API_CATEGORY_SESSION,
     "停止所有 EIM 通信服务"},
    {NULL, NULL, API_CATEGORY_SESSION, NULL}
};

// 通知处理 API
static const api_descriptor_t API_NOTIFICATION[] = {
    {"ipa__notifications_delivery__all_notifications", "发送所有通知", API_CATEGORY_NOTIFICATION,
     "发送所有待处理的 eUICC 通知到 SM-DP+"},
    {"ipa__notifications_delivery__seq_number_single_notification_delivery", 
     "发送单个通知", API_CATEGORY_NOTIFICATION,
     "发送指定序列号的单个通知"},
    {"ipa__notifications_delivery__remove_notification", "移除通知", API_CATEGORY_NOTIFICATION,
     "移除指定序列号的通知"},
    {"ipa__notifications_delivery__remove_all_notifications", "移除所有通知", API_CATEGORY_NOTIFICATION,
     "移除所有待处理的通知"},
    {NULL, NULL, API_CATEGORY_NOTIFICATION, NULL}
};

// Fallback 机制 API
static const api_descriptor_t API_FALLBACK[] = {
    {"ipa__execute_fallback_mechanism", "执行 Fallback", API_CATEGORY_FALLBACK,
     "启用 Fallback Profile"},
    {"ipa__return_from_fallback", "从 Fallback 返回", API_CATEGORY_FALLBACK,
     "恢复正常 Profile 操作"},
    {"ipa__execute_profile_rollback_result", "报告回滚结果", API_CATEGORY_FALLBACK,
     "向 eUICC 报告 Fallback Profile 回滚测试结果"},
    {NULL, NULL, API_CATEGORY_FALLBACK, NULL}
};

// 应急功能 API
static const api_descriptor_t API_EMERGENCY[] = {
    {"ipa__enable_emergency_profile", "启用应急 Profile", API_CATEGORY_EMERGENCY,
     "启用应急 Profile"},
    {"ipa__disable_emergency_profile", "禁用应急 Profile", API_CATEGORY_EMERGENCY,
     "禁用应急 Profile"},
    {NULL, NULL, API_CATEGORY_EMERGENCY, NULL}
};

// 调试功能 API
static const api_descriptor_t API_DEBUG[] = {
    {"debug_set_response", "设置模拟响应", API_CATEGORY_DEBUG,
     "设置手动响应参数注入（调试用）"},
    {NULL, NULL, API_CATEGORY_DEBUG, NULL}
};

// ============================================================================
// 所有 API（用于树形结构）
// ============================================================================

typedef struct {
    const char *category_name;
    const api_descriptor_t *api_list;
} api_category_entry_t;

static const api_category_entry_t ALL_API_CATEGORIES[] = {
    {"信息获取", API_INFO},
    {"Fallback 机制", API_FALLBACK},
    {"应急功能", API_EMERGENCY},
    {"通知处理", API_NOTIFICATION},
    {"初始化", API_INIT},
    {"Profile 管理", API_PROFILE},
    {"会话管理", API_SESSION},
    {"调试功能", API_DEBUG},
    {NULL, NULL}
};

// API 数组总数
#define MAX_API_CATEGORIES 8
#define MAX_API_PER_CATEGORY 20

#endif // APP_API_DEFINITIONS_H
