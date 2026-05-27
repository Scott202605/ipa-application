#ifndef COMMAND_BUILDER_H
#define COMMAND_BUILDER_H

#include "ipa.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 请求数据结构
// ============================================================================

// Profile 下载请求
typedef struct {
    char iccid[32];
    char smdp_address[256];
    char confirmation_code[16];
} profile_download_request_t;

// Profile 启用请求
typedef struct {
    char iccid[32];
} profile_enable_request_t;

// Profile 禁用请求
typedef struct {
    char iccid[32];
} profile_disable_request_t;

// Profile 删除请求
typedef struct {
    char iccid[32];
} profile_delete_request_t;

// 会话创建请求
typedef struct {
    char smdp_address[256];
} session_create_request_t;

// 通知发送请求
typedef struct {
    bool remove_after_send;
    char smdp_address[256];
    uint32_t seq_number;
} notification_send_request_t;

// ============================================================================
// 解析后的数据结构
// ============================================================================

// Profile 信息列表
typedef struct {
    profile_info_t *profiles;
    uint32_t count;
} profile_info_list_t;

// EID 信息
typedef struct {
    char eid_str[33];
    uint8_t eid_bytes[16];
} eid_info_t;

// euiccInfo1 解析结构
typedef struct {
    uint8_t *raw_data;
    uint32_t raw_size;
    char svn[32];
    bool svn_present;
    uint32_t verification_pkid_count;
    uint32_t signing_pkid_count;
    bool verification_list_present;
    bool signing_list_present;
} euicc_info1_parsed_t;

// euiccInfo2 解析结构
typedef struct {
    char profile_version[32];
    char svn[32];
    char euicc_firmware_ver[32];
    char javacard_version[32];
    char gp_version[32];
    uint8_t uicc_capability_mask[32];
    uint8_t rsp_capability_mask[16];
    ipa_euicc_category_t euicc_category;
    int installed_app_count;
    int free_non_volatile_mem;
    int free_volatile_mem;
} euicc_info2_parsed_t;

// 证书信息解析结构
typedef struct {
    uint32_t verification_pkid_count;
    ipa_pkid_t *verification_pkids;
    uint32_t signing_pkid_count;
    ipa_pkid_t *signing_pkids;
} certs_info_parsed_t;

// ============================================================================
// 命令组装函数
// ============================================================================

int build_profile_download_request(
    const char *iccid,
    const char *smdp_address,
    const char *confirmation_code,
    profile_download_request_t *request);

int build_profile_enable_request(
    const char *iccid,
    profile_enable_request_t *request);

int build_profile_disable_request(
    const char *iccid,
    profile_disable_request_t *request);

int build_profile_delete_request(
    const char *iccid,
    profile_delete_request_t *request);

int build_session_create_request(
    const char *smdp_address,
    session_create_request_t *request);

int build_notification_send_request(
    bool remove_after_send,
    const char *smdp_address,
    uint32_t seq_number,
    notification_send_request_t *request);

// ============================================================================
// 响应解析函数
// ============================================================================

int parse_profile_info_list(
    profile_info_t *profiles,
    uint32_t num_profiles,
    profile_info_list_t *out_list);

int parse_eid_string(
    const char *eid_cstring,
    eid_info_t *out_info);

int parse_euicc_info1(
    ipa_euicc_info1_t *info,
    euicc_info1_parsed_t *out_info);

int parse_euicc_info2(
    ipa_euicc_info2_t *info,
    euicc_info2_parsed_t *out_info);

int parse_certs_data(
    ipa_pkid_list_data_t *certs,
    certs_info_parsed_t *out_info);

// ============================================================================
// 工具函数
// ============================================================================

const char* format_profile_state(profile_state_t state);
const char* format_profile_class(profile_class_t class);
const char* format_error_code(ErrCode error_code);

int format_profile_info(
    profile_info_t *profile,
    char *buffer,
    size_t buffer_size);

void free_parsed_data(void);

#ifdef __cplusplus
}
#endif

#endif // COMMAND_BUILDER_H
