#ifndef IPAD_WRAPPER_H
#define IPAD_WRAPPER_H

#include "ipa.h"
#include "ipa_core.h"
#include "ipa_local.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 初始化与反初始化
// ============================================================================

/**
 * @brief 初始化 IPAd SDK
 * @param config_path 配置文件路径（可选，NULL 使用默认配置）
 * @return 0 成功，其他值失败
 */
int ipad_wrapper_init(const char *config_path);

/**
 * @brief 反初始化 IPAd SDK
 */
void ipad_wrapper_deinit(void);

/**
 * @brief 检查 SDK 是否已初始化
 * @return true 已初始化，false 未初始化
 */
bool ipad_wrapper_is_initialized(void);

/**
 * @brief 获取 SDK 版本信息
 * @return 版本字符串
 */
const char* ipad_wrapper_get_version(void);

// ============================================================================
// 设备信息获取
// ============================================================================

/**
 * @brief 获取 eUICC EID
 * @param buffer 存储 EID 的缓冲区
 * @param buffer_size 缓冲区大小（至少 33 字节）
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_eid(char *buffer, uint32_t buffer_size);

/**
 * @brief 获取 euiccInfo1
 * @param out_data 输出结构指针
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_euicc_info_1(ipa_euicc_info1_t *out_data);

/**
 * @brief 获取 euiccInfo2
 * @param out_data 输出结构指针
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_euicc_info_2(ipa_euicc_info2_t *out_data);

/**
 * @brief 获取 eUICC 证书信息
 * @param out_data 输出结构指针
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_certs(ipa_pkid_list_data_t *out_data);

/**
 * @brief 获取所有 Profile 信息
 * @param profiles 输出 Profile 数组指针
 * @param num_profiles 输出 Profile 数量
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_all_profiles_info(profile_info_t **profiles,
                                           uint32_t *num_profiles);

/**
 * @brief 获取 eIM 配置信息
 * @param eim_config 输出配置结构指针
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_get_eim_configuration(eim_configuration_data_t *eim_config);

// ============================================================================
// Fallback 机制
// ============================================================================

/**
 * @brief 执行 Fallback 机制
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_execute_fallback(void);

/**
 * @brief 从 Fallback 返回
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_return_from_fallback(void);

/**
 * @brief 执行 Profile 回滚结果报告
 * @param result 回滚结果结构
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_execute_profile_rollback_result(
    profile_rollback_result_t *result);

// ============================================================================
// 通知管理
// ============================================================================

/**
 * @brief 发送所有待处理通知
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_notifications_delivery_all(void);

/**
 * @brief 发送单个通知
 * @param remove_after_send 发送后是否移除
 * @param smdp_address SM-DP+ 服务器地址
 * @param seq_number 通知序列号
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_notifications_delivery_by_seq(
    bool remove_after_send, 
    const char *smdp_address, 
    uint32_t seq_number);

/**
 * @brief 移除指定通知
 * @param sequence_number 通知序列号
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_notifications_remove(uint32_t sequence_number);

/**
 * @brief 移除所有通知
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_notifications_remove_all(void);

// ============================================================================
// 应急功能
// ============================================================================

/**
 * @brief 启用应急 Profile
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_enable_emergency_profile(void);

/**
 * @brief 禁用应急 Profile
 * @return eOk 成功，其他值失败
 */
ErrCode ipad_wrapper_disable_emergency_profile(void);

// ============================================================================
// 工具函数
// ============================================================================

/**
 * @brief 获取错误码描述字符串
 * @param error_code 错误码
 * @return 错误描述字符串
 */
const char* ipad_wrapper_strerror(ErrCode error_code);

/**
 * @brief 释放 Profile 信息数组
 * @param profiles Profile 数组
 * @param num_profiles Profile 数量
 */
void ipad_wrapper_free_profiles(profile_info_t *profiles, uint32_t num_profiles);

/**
 * @brief 释放 euiccInfo1 数据
 * @param data 数据指针
 */
void ipad_wrapper_free_euicc_info1(ipa_euicc_info1_t *data);

/**
 * @brief 释放 euiccInfo2 数据
 * @param data 数据指针
 */
void ipad_wrapper_free_euicc_info2(ipa_euicc_info2_t *data);

/**
 * @brief 释放证书数据
 * @param data 数据指针
 */
void ipad_wrapper_free_certs(ipa_pkid_list_data_t *data);

#ifdef __cplusplus
}
#endif

#endif // IPAD_WRAPPER_H
