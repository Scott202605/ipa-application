#include "ipad_wrapper.h"
#include "log.h"
#include "es10.h"
#include "es10_typedefs.h"
#include <stdio.h>
#include <string.h>

// SDK 是否已初始化
static bool g_ipa_initialized = false;

// ES10 实例（用于 Profile 管理）
static es10_t *g_es10 = NULL;

// 库配置
static cl_config_t g_cl_config = {
    .es10_driver_selected = ES10_DRIVER_AT,
    .driver_id = NULL,
    .log_level = eLogInfo,
    .initial_refresh_sleep = 1,
    .refresh_max_sleep = 64,
    .esipa_sync_package_retrieval_time = 30
};

int ipad_wrapper_init(const char *config_path) {
    if (g_ipa_initialized) {
        LOGI("IPA 已经初始化");
        return 0;
    }
    
    LOGI("初始化 IPAd SDK, 配置文件：%s", config_path ? config_path : "(默认)");
    
    // 加载配置文件（如果指定）
    if (config_path) {
        LOGI("从文件加载配置：%s", config_path);
    }
    
    // IPA 事件回调
    ipa_event_cb_t event_cb = NULL;
    
    // 初始化库
    int ret = ipa_init_library(&g_cl_config, event_cb);
    if (ret < 0) {
        LOGE("ipa_init_library 失败：%d", ret);
        return ret;
    }
    
    // 创建 ES10 实例（用于 Profile 管理）
    g_es10 = NULL; // 实际使用时需要初始化 smartcard
    
    g_ipa_initialized = true;
    LOGI("IPAd SDK 初始化成功");
    
    return 0;
}

void ipad_wrapper_deinit(void) {
    if (!g_ipa_initialized) {
        LOGW("IPA 未初始化");
        return;
    }
    
    LOGI("反初始化 IPAd SDK");
    
    // 销毁 ES10 实例
    if (g_es10) {
        es10__destroy(g_es10);
        g_es10 = NULL;
    }
    
    // 停止所有通信服务
    stop_eim_service();
    
    // 反初始化库
    ipa_deinit_library();
    
    g_ipa_initialized = false;
    LOGI("IPAd SDK 已反初始化");
}

bool ipad_wrapper_is_initialized(void) {
    return g_ipa_initialized;
}

const char* ipad_wrapper_get_version(void) {
    return "1.1.0"; // 更新版本号
}

// ============================================================================
// Profile 管理 API 实现
// ============================================================================

ErrCode ipad_wrapper_profile_download(
    const char *iccid,
    const char *smdp_address,
    const char *confirmation_code,
    const char *activation_code)
{
    if (!g_ipa_initialized) {
        LOGE("IPA 未初始化");
        return eNotImpl;
    }
    
    if (!iccid || !smdp_address) {
        LOGE("参数错误：iccid 或 smdp_address 为空");
        return eBadArg;
    }
    
    LOGI("下载 Profile: ICCID=%s, SM-DP+=%s", iccid, smdp_address);
    
    // SDK 中需要通过 ES10 接口实现 Profile 下载
    // 这里调用 IPA 层的 API（如果 IPA 层有封装）
    // 或者需要调用 ES10 的 PrepareDownload 和 LoadBoundProfilePackage
    
    // 目前通过 IPA 层的回调函数触发 Profile 下载
    // 实际实现需要结合 SDK 的具体 API
    
    LOGW("Profile 下载功能需要完整的 SM-DP+ 通信实现，当前为框架代码");
    
    // TODO: 实现完整的 Profile 下载流程
    // 1. 通过 HTTP/MQTT/LwM2M 连接 SM-DP+
    // 2. 调用 es10__prepare_download()
    // 3. 下载 Bound Profile Package
    // 4. 调用 es10__load_bound_profile_package()
    
    return eNotImpl; // 框架代码，待完整实现
}

ErrCode ipad_wrapper_profile_enable(const char *iccid)
{
    if (!g_ipa_initialized) {
        LOGE("IPA 未初始化");
        return eNotImpl;
    }
    
    if (!iccid) {
        LOGE("参数错误：iccid 为空");
        return eBadArg;
    }
    
    LOGI("启用 Profile: ICCID=%s", iccid);
    
    // 调用 ES10 的 EnableProfile API
    // 需要初始化 smartcard 和 ES10 实例
    
    if (g_es10 != NULL) {
        // es10__enable_profile(g_es10, iccid, ...);
        LOGI("调用 ES10 EnableProfile（框架代码）");
    }
    
    return eNotImpl; // 框架代码，待完整实现
}

ErrCode ipad_wrapper_profile_disable(const char *iccid)
{
    if (!g_ipa_initialized) {
        LOGE("IPA 未初始化");
        return eNotImpl;
    }
    
    if (!iccid) {
        LOGE("参数错误：iccid 为空");
        return eBadArg;
    }
    
    LOGI("禁用 Profile: ICCID=%s", iccid);
    
    if (g_es10 != NULL) {
        // es10__disable_profile(g_es10, iccid, ...);
        LOGI("调用 ES10 DisableProfile（框架代码）");
    }
    
    return eNotImpl; // 框架代码，待完整实现
}

ErrCode ipad_wrapper_profile_delete(const char *iccid)
{
    if (!g_ipa_initialized) {
        LOGE("IPA 未初始化");
        return eNotImpl;
    }
    
    if (!iccid) {
        LOGE("参数错误：iccid 为空");
        return eBadArg;
    }
    
    LOGI("删除 Profile: ICCID=%s", iccid);
    
    if (g_es10 != NULL) {
        // es10__delete_profile(g_es10, iccid);
        LOGI("调用 ES10 DeleteProfile（框架代码）");
    }
    
    return eNotImpl; // 框架代码，待完整实现
}

// ============================================================================
// 会话管理 API 实现
// ============================================================================

ErrCode ipad_wrapper_connect_mqtt(
    const char *hostname,
    int port,
    const char *username,
    const char *password,
    bool use_tls)
{
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!hostname) {
        return eBadArg;
    }
    
    LOGI("连接 MQTT 服务：%s:%d (TLS: %s)", hostname, port, use_tls ? "是" : "否");
    
    ipa_config_mqtt_t config = {0};
    snprintf(config.hostname, sizeof(config.hostname), "%s", hostname);
    snprintf(config.protocol, sizeof(config.protocol), "%s", use_tls ? "mqtts" : "mqtt");
    config.port = port;
    
    if (username) {
        strncpy(config.username, username, sizeof(config.username) - 1);
    }
    if (password) {
        strncpy(config.password, password, sizeof(config.password) - 1);
    }
    
    ErrCode ret = connect_mqtt_service(&config);
    if (ret == eOk) {
        LOGI("MQTT 连接成功");
    } else {
        LOGE("MQTT 连接失败：%s", ipad_wrapper_strerror(ret));
    }
    
    return ret;
}

ErrCode ipad_wrapper_connect_lwm2m(
    const char *hostname,
    int port,
    const char *client_name,
    bool use_dtls)
{
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!hostname || !client_name) {
        return eBadArg;
    }
    
    LOGI("连接 LwM2M 服务：%s:%d (DTLS: %s, Client: %s)", 
         hostname, port, use_dtls ? "是" : "否", client_name);
    
    ipa_config_lwm2m_t config = {0};
    snprintf(config.hostname, sizeof(config.hostname), "%s", hostname);
    config.port = port;
    config.dtls = use_dtls;
    config.bootstrap = false;
    config.ipv4 = true;
    strncpy(config.client_name, client_name, sizeof(config.client_name) - 1);
    
    ErrCode ret = connect_lwm2m_service(&config);
    if (ret == eOk) {
        LOGI("LwM2M 连接成功");
    } else {
        LOGE("LwM2M 连接失败：%s", ipad_wrapper_strerror(ret));
    }
    
    return ret;
}

ErrCode ipad_wrapper_connect_http(
    const char *fqdn,
    uint32_t max_timeout,
    uint32_t http_timeout)
{
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!fqdn) {
        return eBadArg;
    }
    
    LOGI("连接 HTTP 服务：%s (超时：%u 秒)", fqdn, http_timeout);
    
    ipa_config_http_t config = {0};
    snprintf(config.fqdn, sizeof(config.fqdn), "%s", fqdn);
    config.max_time_without_transmission = max_timeout;
    config.http_timeout = http_timeout;
    config.sync_sleep_time = 10;
    
    ErrCode ret = connect_http_service(&config);
    if (ret == eOk) {
        LOGI("HTTP 连接成功");
    } else {
        LOGE("HTTP 连接失败：%s", ipad_wrapper_strerror(ret));
    }
    
    return ret;
}

void ipad_wrapper_stop_eim_service(void) {
    LOGI("停止 EIM 服务");
    stop_eim_service();
}

// ============================================================================
// 其他 API 实现（保持不变）
// ============================================================================

ErrCode ipad_wrapper_get_eid(char *buffer, uint32_t buffer_size) {
    if (!g_ipa_initialized) {
        LOGE("IPA 未初始化");
        return eNotImpl;
    }
    
    if (!buffer || buffer_size < 33) {
        LOGE("参数错误");
        return eBadArg;
    }
    
    return ipa__get_eid_cstring(buffer, buffer_size);
}

ErrCode ipad_wrapper_get_euicc_info_1(ipa_euicc_info1_t *out_data) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!out_data) {
        return eBadArg;
    }
    
    return ipa__get_euicc_info_1(out_data);
}

ErrCode ipad_wrapper_get_euicc_info_2(ipa_euicc_info2_t *out_data) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!out_data) {
        return eBadArg;
    }
    
    return ipa__get_euicc_info_2(out_data);
}

ErrCode ipad_wrapper_get_certs(ipa_pkid_list_data_t *out_data) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!out_data) {
        return eBadArg;
    }
    
    return ipa__get_certs(out_data);
}

ErrCode ipad_wrapper_get_all_profiles_info(profile_info_t **profiles,
                                           uint32_t *num_profiles) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!profiles || !num_profiles) {
        return eBadArg;
    }
    
    return ipa__get_all_profiles_info(profiles, num_profiles, NULL);
}

ErrCode ipad_wrapper_get_eim_configuration(eim_configuration_data_t *eim_config) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!eim_config) {
        return eBadArg;
    }
    
    return ipa__get_eim_configuration(eim_config, NULL);
}

ErrCode ipad_wrapper_execute_fallback(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__execute_fallback_mechanism();
}

ErrCode ipad_wrapper_return_from_fallback(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__return_from_fallback();
}

ErrCode ipad_wrapper_execute_profile_rollback_result(
    profile_rollback_result_t *result) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!result) {
        return eBadArg;
    }
    
    return ipa__execute_profile_rollback_result(result);
}

ErrCode ipad_wrapper_notifications_delivery_all(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__notifications_delivery__all_notifications();
}

ErrCode ipad_wrapper_notifications_delivery_by_seq(
    bool remove_after_send, 
    const char *smdp_address, 
    uint32_t seq_number) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    if (!smdp_address) {
        return eBadArg;
    }
    
    return ipa__notifications_delivery__seq_number_single_notification_delivery(
        remove_after_send, smdp_address, seq_number);
}

ErrCode ipad_wrapper_notifications_remove(uint32_t sequence_number) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__notifications_delivery__remove_notification(sequence_number);
}

ErrCode ipad_wrapper_notifications_remove_all(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__notifications_delivery__remove_all_notifications();
}

ErrCode ipad_wrapper_enable_emergency_profile(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__enable_emergency_profile();
}

ErrCode ipad_wrapper_disable_emergency_profile(void) {
    if (!g_ipa_initialized) {
        return eNotImpl;
    }
    
    return ipa__disable_emergency_profile();
}

const char* ipad_wrapper_strerror(ErrCode error_code) {
    switch (error_code) {
        case eOk: return "成功";
        case eFatal: return "致命错误";
        case eNotSupported: return "不支持";
        case eNotImpl: return "未实现";
        case eBadArg: return "参数错误";
        case eJsonParseError: return "JSON 解析错误";
        case eSessionCancelled: return "会话已取消";
        case eNotEnoughBuffer: return "缓冲区不足";
        case eNoData: return "无数据";
        case eNoMem: return "内存不足";
        case eSimBusy: return "SIM 卡忙";
        case eInvalidFormat: return "格式无效";
        default: return "未知错误";
    }
}

void ipad_wrapper_free_profiles(profile_info_t *profiles, uint32_t num_profiles) {
    (void)profiles;
    (void)num_profiles;
}

void ipad_wrapper_free_euicc_info1(ipa_euicc_info1_t *data) {
    if (data) {
        ipa__free_euicc_info1_data(data);
    }
}

void ipad_wrapper_free_euicc_info2(ipa_euicc_info2_t *data) {
    if (data) {
        ipa__free_euicc_info2_data(data);
    }
}

void ipad_wrapper_free_certs(ipa_pkid_list_data_t *data) {
    if (data) {
        ipa__free_certs_data(data);
    }
}
