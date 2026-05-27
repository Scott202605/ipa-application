#include "ipad_wrapper.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

// SDK 是否已初始化
static bool g_ipa_initialized = false;

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
    
    LOGI("初始化 IPAd SDK, 配置文件: %s", config_path ? config_path : "(默认)");
    
    // 加载配置文件（如果指定）
    if (config_path) {
        // TODO: 从配置文件加载配置
        LOGI("从文件加载配置: %s", config_path);
    }
    
    // IPA 事件回调
    ipa_event_cb_t event_cb = NULL; // TODO: 实现事件回调
    
    // 初始化库
    int ret = ipa_init_library(&g_cl_config, event_cb);
    if (ret < 0) {
        LOGE("ipa_init_library 失败：%d", ret);
        return ret;
    }
    
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
    return "1.0.0";
}

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
    // TODO: 实现 Profile 信息释放
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
