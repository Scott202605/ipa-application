# IPA SDK API 参考文档

## API 列表

### 初始化类 API

#### ipa__return_from_fallback()

**功能**: 从 Fallback Profile 返回到正常 Profile

**原型**:
```c
ErrCode ipa__return_from_fallback();
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误
- `eNotImpl`: 未实现

---

#### ipa__execute_fallback_mechanism()

**功能**: 执行 Fallback 机制，启用 Fallback Profile

**原型**:
```c
ErrCode ipa__execute_fallback_mechanism(void);
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误
- `eNotImpl`: 未实现

---

### 信息获取类 API

#### ipa__get_certs()

**功能**: 获取 eUICC 证书信息（EUM 和 eUICC 证书）

**原型**:
```c
ErrCode ipa__get_certs(ipa_pkid_list_data_t *out_data);
```

**参数**:
- `out_data` [输出]: PKID 列表数据结构

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eFatal`: 致命错误

**示例**:
```c
ipa_pkid_list_data_t certs;
ErrCode ret = ipa__get_certs(&certs);
if (ret == eOk) {
    // 使用证书信息
    ipa__free_certs_data(&certs);
}
```

---

#### ipa__get_all_profiles_info()

**功能**: 获取所有已安装 Profile 的信息

**原型**:
```c
ErrCode ipa__get_all_profiles_info(
    profile_info_t **profiles,
    uint32_t *num_profiles,
    uint8_t **profile_info_list_response_tlv_out
);
```

**参数**:
- `profiles` [输出]: Profile 信息数组指针
- `num_profiles` [输出]: Profile 数量
- `profile_info_list_response_tlv_out` [输出]: TLV 格式响应数据

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eNoMem`: 内存不足

**示例**:
```c
profile_info_t *profiles;
uint32_t num_profiles;
ErrCode ret = ipa__get_all_profiles_info(&profiles, &num_profiles, NULL);
if (ret == eOk) {
    for (uint32_t i = 0; i < num_profiles; i++) {
        printf("Profile %u: State=%d\n", i, profiles[i].profile_state);
    }
}
```

---

#### ipa__get_eim_configuration()

**功能**: 获取 eIM 配置信息

**原型**:
```c
ErrCode ipa__get_eim_configuration(
    eim_configuration_data_t *eim_configuration_info,
    uint8_t **response_tlv_out
);
```

**参数**:
- `eim_configuration_info` [输出]: eIM 配置数据结构
- `response_tlv_out` [输出]: TLV 格式响应数据

**返回值**:
- `eOk`: 成功
- `eNotFound`: 未找到 eIM 配置
- `eBadArg`: 参数错误

---

#### ipa__get_euicc_info_1()

**功能**: 获取 euiccInfo1 数据（eUICC 识别、能力、安全信息）

**原型**:
```c
ErrCode ipa__get_euicc_info_1(ipa_euicc_info1_t *out_data);
```

**参数**:
- `out_data` [输出]: euiccInfo1 数据结构

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eFatal`: 致命错误

**数据结构**:
```c
typedef struct {
    uint8_t *raw;                  // 原始数据
    uint32_t raw_size;
    uint8_t *svn;                  // 安全版本号
    uint32_t svn_size;
    bool svn_present;
    ipa_pkid_list_t ci_pkid_list_for_verification;  // 验证用 PKID 列表
    bool verification_list_present;
    ipa_pkid_list_t ci_pkid_list_for_signing;       // 签名用 PKID 列表
    bool signing_list_present;
} ipa_euicc_info1_t;
```

---

#### ipa__get_euicc_info_2()

**功能**: 获取 euiccInfo2 数据（eUICC 能力、版本、证书）

**原型**:
```c
ErrCode ipa__get_euicc_info_2(ipa_euicc_info2_t *out_data);
```

**参数**:
- `out_data` [输出]: euiccInfo2 数据结构

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eFatal`: 致命错误

**数据结构**:
```c
typedef struct {
    char *profile_version;
    char *svn;
    char *euicc_firmware_ver;
    char *pp_version;
    char *sas_acreditation_number;
    ipa_ext_card_resources_t ext_card_res_info;
    uint8_t uicc_capability_mask[32];
    uint8_t rsp_capability_mask[16];
    ipa_pkid_list_data_t ipa_pkid_list_data;
    char *javacard_version;
    char *globalplatform_version;
    ipa_euicc_category_t euicc_category;
    bool euicc_category_present;
    uint8_t *forbidden_pprs;
    bool forbidden_pprs_present;
} ipa_euicc_info2_t;
```

---

#### ipa__get_eid_cstring()

**功能**: 获取 eUICC EID（十六进制字符串）

**原型**:
```c
ErrCode ipa__get_eid_cstring(char *buffer, uint32_t buffer_size);
```

**参数**:
- `buffer` [输出]: EID 字符串缓冲区（至少 33 字节）
- `buffer_size` [输入]: 缓冲区大小

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eNotImpl`: 未实现

**示例**:
```c
char eid[33];
ErrCode ret = ipa__get_eid_cstring(eid, sizeof(eid));
if (ret == eOk) {
    printf("EID: %s\n", eid);
}
```

---

### 通知管理类 API

#### ipa__notifications_delivery__all_notifications()

**功能**: 发送所有待处理的 eUICC 通知到 SM-DP+

**原型**:
```c
ErrCode ipa__notifications_delivery__all_notifications();
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误
- `eNotImpl`: 未实现

---

#### ipa__notifications_delivery__seq_number_single_notification_delivery()

**功能**: 发送指定序列号的单个通知

**原型**:
```c
ErrCode ipa__notifications_delivery__seq_number_single_notification_delivery(
    bool remove_after_send,
    const char *smdp_address,
    uint32_t seq_number
);
```

**参数**:
- `remove_after_send` [输入]: 发送后是否移除通知
- `smdp_address` [输入]: SM-DP+ 服务器地址
- `seq_number` [输入]: 通知序列号

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eFatal`: 致命错误

**示例**:
```c
ErrCode ret = ipa__notifications_delivery__seq_number_single_notification_delivery(
    true,  // 发送后移除
    "smdp.example.com",
    12345  // 序列号
);
```

---

#### ipa__notifications_delivery__remove_notification()

**功能**: 移除指定序列号的通知

**原型**:
```c
ErrCode ipa__notifications_delivery__remove_notification(uint32_t sequence_number);
```

**参数**:
- `sequence_number` [输入]: 要移除的通知序列号

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误

---

#### ipa__notifications_delivery__remove_all_notifications()

**功能**: 移除所有待处理的通知

**原型**:
```c
ErrCode ipa__notifications_delivery__remove_all_notifications();
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误

---

### 应急功能 API

#### ipa__enable_emergency_profile()

**功能**: 启用应急 Profile

**原型**:
```c
ErrCode ipa__enable_emergency_profile();
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误
- `eNotImpl`: 未实现

---

#### ipa__disable_emergency_profile()

**功能**: 禁用应急 Profile

**原型**:
```c
ErrCode ipa__disable_emergency_profile();
```

**参数**: 无

**返回值**:
- `eOk`: 成功
- `eFatal`: 致命错误
- `eNotImpl`: 未实现

---

### Profile 回滚 API

#### ipa__execute_profile_rollback_result()

**功能**: 向 eUICC 报告 Fallback Profile 回滚测试结果

**原型**:
```c
ErrCode ipa__execute_profile_rollback_result(profile_rollback_result_t *result);
```

**参数**:
- `result` [输入]: 回滚测试结果结构

**返回值**:
- `eOk`: 成功
- `eBadArg`: 参数错误
- `eNotImpl`: 未实现

**数据结构**:
```c
typedef struct {
    // 根据实际 SDK 定义
} profile_rollback_result_t;
```

---

## 错误码参考

| 错误码 | 值 | 说明 |
|--------|-----|------|
| `eOk` | 0 | 成功 |
| `eFatal` | 1 | 致命错误 |
| `eNotSupported` | 2 | 不支持 |
| `eNotImpl` | 3 | 未实现 |
| `eBadArg` | 4 | 参数错误 |
| `eJsonParseError` | 5 | JSON 解析错误 |
| `eSessionCancelled` | 6 | 会话已取消 |
| `eNotEnoughBuffer` | 7 | 缓冲区不足 |
| `eNoData` | 8 | 无数据 |
| `eNoMem` | 9 | 内存不足 |
| `eSimBusy` | 10 | SIM 卡忙 |
| `eInvalidFormat` | 11 | 格式无效 |

---

## 数据类型

### ErrCode

```c
typedef enum {
    eOk = 0,
    eFatal = 1,
    eNotSupported = 2,
    eNotImpl = 3,
    eBadArg = 4,
    eJsonParseError = 5,
    eSessionCancelled = 6,
    eNotEnoughBuffer = 7,
    eNoData = 8,
    eNoMem = 9,
    eSimBusy = 10,
    eInvalidFormat = 11
} ErrCode;
```

### profile_info_t

Profile 信息结构（详细字段见 `es10_typedefs.h`）:

```c
typedef struct {
    iccid_t iccid;                          // ICCID
    isdp_aid_t isdp_aid;                    // ISDP AID
    profile_state_t profile_state;          // Profile 状态
    profile_nickname_t profile_nickname;    // Profile 昵称
    service_provider_name_t service_provider_name;  // 服务提供商名称
    profile_name_t profile_name;            // Profile 名称
    icon_t icon;                            // 图标
    icon_type_t icon_type;                  // 图标类型
    profile_class_t profile_class;          // Profile 类别
    operator_id_t profile_owner;            // Profile 所有者
    // ... 其他字段
} profile_info_t;
```

---

## 使用示例

### 示例 1: 获取 EID

```c
#include "ipa.h"

int main(void) {
    // 初始化
    cl_config_t config = {0};
    ipa_init_library(&config, NULL);
    
    // 获取 EID
    char eid[33];
    ErrCode ret = ipa__get_eid_cstring(eid, sizeof(eid));
    
    if (ret == eOk) {
        printf("EID: %s\n", eid);
    } else {
        fprintf(stderr, "获取 EID 失败：%d\n", ret);
    }
    
    // 反初始化
    ipa_deinit_library();
    return 0;
}
```

### 示例 2: 获取所有 Profile 信息

```c
#include "ipa.h"

void list_all_profiles(void) {
    profile_info_t *profiles = NULL;
    uint32_t num_profiles = 0;
    
    ErrCode ret = ipa__get_all_profiles_info(&profiles, &num_profiles, NULL);
    
    if (ret == eOk) {
        printf("找到 %u 个 Profile:\n", num_profiles);
        
        for (uint32_t i = 0; i < num_profiles; i++) {
            printf("Profile %u:\n", i);
            printf("  状态：%s\n", 
                   profiles[i].profile_state == PROFILE_STATE_ENABLED ? 
                   "已启用" : "已禁用");
            printf("  类别：%d\n", profiles[i].profile_class);
            // ... 打印其他信息
        }
    }
    
    // 释放内存（如果需要）
}
```

### 示例 3: 发送所有通知

```c
#include "ipa.h"

int send_all_notifications(void) {
    ErrCode ret = ipa__notifications_delivery__all_notifications();
    
    if (ret == eOk) {
        printf("所有通知已成功发送\n");
        return 0;
    } else if (ret == eNoData) {
        printf("没有待处理的通知\n");
        return 0;
    } else {
        fprintf(stderr, "发送通知失败：%d\n", ret);
        return -1;
    }
}
```

