/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once

#include "typedefs.h"

typedef enum profile_state_e {
    PROFILE_STATE_DISABLED = 0,
    PROFILE_STATE_ENABLED = 1,
} profile_state_t;

typedef struct profile_nickname_s {
    unsigned char value[PROFILE_NICKNAME_UTF8_STRING_MAX_SIZE];
    uint8_t len;
} profile_nickname_t;

typedef struct service_provider_name_s {
    unsigned char value[PROFILE_SERVICE_PROVIDER_NAME_UTF8_STRING_MAX_SIZE];
    uint8_t len;
} service_provider_name_t;

typedef struct profile_name_s {
    unsigned char value[PROFILE_NAME_UTF8_STRING_MAX_SIZE];
    uint8_t len;
} profile_name_t;

typedef struct icon_s {
    uint8_t value[ICON_OCTET_STRING_MAX_SIZE];
    uint16_t size;
} icon_t;

typedef enum icon_type_e {
    ICON_TYPE_JPG = 0,
    ICON_TYPE_PNG = 1,
} icon_type_t;

typedef enum profile_class_s {
    PROFILE_CLASS_TEST = 0,
    PROFILE_CLASS_PROVISIONING = 1,
    PROFILE_CLASS_OPERATIONAL = 2
} profile_class_t;

typedef struct mcc_mnc_s {
    uint8_t value[MCC_MNC_SIZE];
} mcc_mnc_t;

typedef struct operator_id_data_presence_s {
    bool gid1;
    bool gid2;
} operator_id_data_presence_t;

typedef struct operator_id_s {
    mcc_mnc_t mcc_mnc;
    uint8_t *gid1;
    uint32_t gid1_size;
    uint8_t *gid2;
    uint32_t gid2_size;
    operator_id_data_presence_t field_is_present;
} operator_id_t;

typedef struct dp_propietary_data_s {
    uint8_t dp_oid[DP_PROPIETARY_DATA_MAX_SIZE];
    uint8_t dp_oid_size;
} dp_propietary_data_t;

typedef struct ppr_ids_s {
    bool ppr_update_control;
    bool ppr1;
    bool ppr2;
} ppr_ids_t;

typedef struct profile_info_data_presence_s {
    bool iccid;
    bool isdp_aid;
    bool profile_state;
    bool profile_nickname;
    bool service_provider_name;
    bool profile_name;
    bool icon_type;
    bool icon;
    bool profile_class;
    bool notification_configuration_info;
    bool profile_owner;
    bool dp_propietary_data;
    bool profile_policy_rules;
    bool ecall_indication;
    bool fallback_attribute;
    bool fallback_allowed;
} profile_info_data_presence_t;

typedef struct profile_info_s {
    iccid_t iccid;
    isdp_aid_t isdp_aid;
    profile_state_t profile_state;
    profile_nickname_t profile_nickname;
    service_provider_name_t service_provider_name;
    profile_name_t profile_name;
    icon_t icon;
    icon_type_t icon_type;
    profile_class_t profile_class;
    asn1_list_iterator_t notification_configuration_info;
    operator_id_t profile_owner;
    dp_propietary_data_t dp_propietary_data;
    ppr_ids_t profile_policy_rules;
    bool ecall_indication;
    bool fallback_attribute;
    bool fallback_allowed;
    profile_info_data_presence_t field_is_present;
} profile_info_t;

typedef enum eim_id_type_e {
    EIM_ID_TYPE_OID = 1,
    EIM_ID_TYPE_FQDN = 2,
    EIM_ID_TYPE_PROPIETARY = 3
} eim_id_type_t;

typedef enum eim_public_key_data_type_e {
    EIM_PUBLIC_KEY_CHOICE,
    EIM_CERTIFICATE_CHOICE
} eim_public_key_data_choice_t;

typedef struct eim_public_key_data_s {
    uint8_t *value;
    uint32_t value_size;
    eim_public_key_data_choice_t choice;
} eim_public_key_data_t;

typedef enum trusted_public_key_data_tls_type_e {
    TRUSTED_EIM_PK_TLS_CHOICE,
    TRUSTED_CERTIFICATE_TLS_CHOICE
} trusted_public_key_data_tls_choice_t;

typedef struct trusted_public_key_data_tls_s {
    uint8_t *value;
    uint32_t value_size;
    trusted_public_key_data_tls_choice_t choice;
} trusted_public_key_data_tls_t;

typedef struct eim_supported_protocol_e {
    bool eim_retrieve_https;
    bool eim_retrieve_coaps;
    bool eim_inject_https;
    bool eim_inject_coaps;
    bool eim_proprietary;
} eim_supported_protocol_t;

typedef struct eim_configuration_data_presence_s {
    bool eim_fqdn;
    bool eim_id_type;
    bool counter_value;
    bool association_token;
    bool eim_public_key_data;
    bool trusted_public_key_data_tls;
    bool eim_supported_protocol;
    bool euicc_ci_pk_id;
    bool indirect_profile_download;
} eim_configuration_data_presence_t;

typedef struct eim_configuration_data_s {
    unsigned char *eim_id;
    uint32_t eim_id_len;
    unsigned char *eim_fqdn;
    uint32_t eim_fqdn_len;
    eim_id_type_t eim_id_type;
    uint32_t counter_value;
    uint32_t association_token;
    eim_public_key_data_t eim_public_key_data;
    trusted_public_key_data_tls_t trusted_public_key_data_tls;
    eim_supported_protocol_t eim_supported_protocol;
    subject_key_identifier_t euicc_ci_pk_id;
    eim_configuration_data_presence_t field_is_present;
} eim_configuration_data_t;

typedef struct set_default_dp_address_request_s {
    unsigned char *default_dp_address;
    uint32_t default_dp_address_len;
} set_default_dp_address_request_t;

typedef struct {
    const char *eim_id;
    const char *eim_fqdn;
    const char *eim_public_key_base64;
    eim_public_key_data_choice_t choice;
    int eim_id_type;
    uint32_t counter_value;
    eim_supported_protocol_t eim_supported_protocol;
    bool indirect_profile_download;
} eim_config_t;

typedef enum profile_rollback_result_e {
    PROFILE_ROLLBACK_RESULT_OK = 0,
    PROFILE_ROLLBACK_RESULT_ROLLBACK_NOT_ALLOWED = 1,
    PROFILE_ROLLBACK_RESULT_CAT_BUSY = 5,
    PROFILE_ROLLBACK_RESULT_COMMAND_ERROR = 7,
    PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR = 127
} profile_rollback_result_t;

typedef struct euicc_memory_reset_request_s {
    bool delete_operational_profiles;
    bool delete_field_loaded_test_profiles;
    bool reset_default_smdp_address;

    bool delete_preloaded_test_profiles;
    bool delete_provisioning_profiles;
    bool reset_eim_config_data;
    bool reset_immediate_enable_config;
} euicc_memory_reset_request_t;

typedef struct {
    const char *smdp_oid;
    const char *smdp_address;
    bool immediate_enable_flag;
} profile_enabling_config_t;
