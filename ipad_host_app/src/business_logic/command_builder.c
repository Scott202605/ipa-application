#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "command_builder.h"
#include "ipad_wrapper.h"

// ============================================================================
// 命令组装模块
// ============================================================================

// 构建 Profile 下载请求
int build_profile_download_request(
    const char *iccid,
    const char *smdp_address,
    const char *confirmation_code,
    profile_download_request_t *request) 
{
    if (!iccid || !smdp_address || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    
    // ICCID
    strncpy(request->iccid, iccid, sizeof(request->iccid) - 1);
    
    // SM-DP+ 地址
    strncpy(request->smdp_address, smdp_address, 
            sizeof(request->smdp_address) - 1);
    
    // 确认码（可选）
    if (confirmation_code) {
        strncpy(request->confirmation_code, confirmation_code,
                sizeof(request->confirmation_code) - 1);
    }
    
    return 0;
}

// 构建 Profile 启用请求
int build_profile_enable_request(
    const char *iccid,
    profile_enable_request_t *request)
{
    if (!iccid || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    strncpy(request->iccid, iccid, sizeof(request->iccid) - 1);
    
    return 0;
}

// 构建 Profile 禁用请求
int build_profile_disable_request(
    const char *iccid,
    profile_disable_request_t *request)
{
    if (!iccid || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    strncpy(request->iccid, iccid, sizeof(request->iccid) - 1);
    
    return 0;
}

// 构建 Profile 删除请求
int build_profile_delete_request(
    const char *iccid,
    profile_delete_request_t *request)
{
    if (!iccid || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    strncpy(request->iccid, iccid, sizeof(request->iccid) - 1);
    
    return 0;
}

// 构建会话创建请求
int build_session_create_request(
    const char *smdp_address,
    session_create_request_t *request)
{
    if (!smdp_address || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    strncpy(request->smdp_address, smdp_address,
            sizeof(request->smdp_address) - 1);
    
    return 0;
}

// 构建通知发送请求
int build_notification_send_request(
    bool remove_after_send,
    const char *smdp_address,
    uint32_t seq_number,
    notification_send_request_t *request)
{
    if (!smdp_address || !request) {
        return -1;
    }
    
    memset(request, 0, sizeof(*request));
    request->remove_after_send = remove_after_send;
    strncpy(request->smdp_address, smdp_address,
            sizeof(request->smdp_address) - 1);
    request->seq_number = seq_number;
    
    return 0;
}

// ============================================================================
// 响应解析模块
// ============================================================================

// 解析 Profile 信息列表
int parse_profile_info_list(
    profile_info_t *profiles,
    uint32_t num_profiles,
    profile_info_list_t *out_list)
{
    if (!profiles || num_profiles == 0 || !out_list) {
        return -1;
    }
    
    out_list->profiles = profiles;
    out_list->count = num_profiles;
    
    return 0;
}

// 解析 EID 字符串
int parse_eid_string(
    const char *eid_cstring,
    eid_info_t *out_info)
{
    if (!eid_cstring || !out_info) {
        return -1;
    }
    
    size_t len = strlen(eid_cstring);
    if (len != 32) {  // EID 应该是 32 个十六进制字符
        return -1;
    }
    
    strncpy(out_info->eid_str, eid_cstring, sizeof(out_info->eid_str) - 1);
    
    // 解析为字节数组
    for (int i = 0; i < 16; i++) {
        char byte_str[3] = {eid_cstring[i*2], eid_cstring[i*2+1], '\0'};
        out_info->eid_bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    
    return 0;
}

// 解析 euiccInfo1
int parse_euicc_info1(
    ipa_euicc_info1_t *info,
    euicc_info1_parsed_t *out_info)
{
    if (!info || !out_info) {
        return -1;
    }
    
    memset(out_info, 0, sizeof(*out_info));
    
    // 复制原始数据指针
    out_info->raw_data = info->raw;
    out_info->raw_size = info->raw_size;
    
    // SVN
    if (info->svn_present && info->svn) {
        strncpy(out_info->svn, (char*)info->svn, sizeof(out_info->svn) - 1);
    }
    
    // PKID 列表
    out_info->verification_list_present = info->verification_list_present;
    out_info->signing_list_present = info->signing_list_present;
    
    if (info->verification_list_present) {
        out_info->verification_pkid_count = info->ci_pkid_list_for_verification.count;
    }
    
    if (info->signing_list_present) {
        out_info->signing_pkid_count = info->ci_pkid_list_for_signing.count;
    }
    
    return 0;
}

// 解析 euiccInfo2
int parse_euicc_info2(
    ipa_euicc_info2_t *info,
    euicc_info2_parsed_t *out_info)
{
    if (!info || !out_info) {
        return -1;
    }
    
    memset(out_info, 0, sizeof(*out_info));
    
    // 版本信息
    if (info->profile_version) {
        strncpy(out_info->profile_version, info->profile_version,
                sizeof(out_info->profile_version) - 1);
    }
    if (info->svn) {
        strncpy(out_info->svn, info->svn, sizeof(out_info->svn) - 1);
    }
    if (info->euicc_firmware_ver) {
        strncpy(out_info->euicc_firmware_ver, info->euicc_firmware_ver,
                sizeof(out_info->euicc_firmware_ver) - 1);
    }
    if (info->javacard_version) {
        strncpy(out_info->javacard_version, info->javacard_version,
                sizeof(out_info->javacard_version) - 1);
    }
    if (info->globalplatform_version) {
        strncpy(out_info->gp_version, info->globalplatform_version,
                sizeof(out_info->gp_version) - 1);
    }
    
    // 能力信息
    memcpy(out_info->uicc_capability_mask, info->uicc_capability_mask,
           sizeof(out_info->uicc_capability_mask));
    memcpy(out_info->rsp_capability_mask, info->rsp_capability_mask,
           sizeof(out_info->rsp_capability_mask));
    
    // eUICC 类别
    out_info->euicc_category = info->euicc_category;
    
    // 资源信息
    out_info->installed_app_count = info->ext_card_res_info.installed_app_number;
    out_info->free_non_volatile_mem = info->ext_card_res_info.free_non_volatile_mem;
    out_info->free_volatile_mem = info->ext_card_res_info.free_volatile_mem;
    
    return 0;
}

// 解析证书数据
int parse_certs_data(
    ipa_pkid_list_data_t *certs,
    certs_info_parsed_t *out_info)
{
    if (!certs || !out_info) {
        return -1;
    }
    
    memset(out_info, 0, sizeof(*out_info));
    
    // 验证用 PKID 列表
    if (certs->ci_pkid_list_for_verification.items) {
        out_info->verification_pkid_count = certs->ci_pkid_list_for_verification.count;
        out_info->verification_pkids = certs->ci_pkid_list_for_verification.items;
    }
    
    // 签名用 PKID 列表
    if (certs->ci_pkid_list_for_signing.items) {
        out_info->signing_pkid_count = certs->ci_pkid_list_for_signing.count;
        out_info->signing_pkids = certs->ci_pkid_list_for_signing.items;
    }
    
    return 0;
}

// 格式化 Profile 状态字符串
const char* format_profile_state(profile_state_t state)
{
    switch (state) {
        case PROFILE_STATE_ENABLED:
            return "已启用";
        case PROFILE_STATE_DISABLED:
            return "已禁用";
        default:
            return "未知";
    }
}

// 格式化 Profile 类别字符串
const char* format_profile_class(profile_class_t class)
{
    switch (class) {
        case PROFILE_CLASS_TEST:
            return "测试";
        case PROFILE_CLASS_PROVISIONING:
            return "配置";
        case PROFILE_CLASS_OPERATIONAL:
            return "运营";
        default:
            return "未知";
    }
}

// 格式化错误码字符串
const char* format_error_code(ErrCode error_code)
{
    return ipad_wrapper_strerror(error_code);
}

// 将 Profile 信息转换为可读字符串
int format_profile_info(
    profile_info_t *profile,
    char *buffer,
    size_t buffer_size)
{
    if (!profile || !buffer || buffer_size < 512) {
        return -1;
    }
    
    memset(buffer, 0, buffer_size);
    
    char iccid_str[21] = {0};
    char isdp_aid_hex[33] = {0};
    
    // ICCID 转字符串（如果需要）
    // 这里简化处理，实际需要根据具体编码转换
    
    // ISDP AID 转十六进制
    for (int i = 0; i < 16 && i < ISDP_AID_SIZE; i++) {
        sprintf(isdp_aid_hex + i*2, "%02X", profile->isdp_aid.value[i]);
    }
    
    snprintf(buffer, buffer_size,
             "Profile 信息:\n"
             "  ICCID: %s\n"
             "  ISDP AID: %s\n"
             "  状态：%s\n"
             "  类别：%s\n"
             "  图标类型：%d\n"
             "  回滚属性：%s\n",
             iccid_str,
             isdp_aid_hex,
             format_profile_state(profile->profile_state),
             format_profile_class(profile->profile_class),
             profile->icon_type,
             profile->fallback_attribute ? "是" : "否");
    
    return 0;
}

// 释放解析后的数据
void free_parsed_data(void)
{
    // 大多数解析数据只是指针引用，不需要释放
    // 如果需要分配内存，在这里释放
}
