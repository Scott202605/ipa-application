/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once

#include "typedefs.h"
#include "tlv_values.h"
#include "sha256.h"
#include "device_info.h"

#define PROFILE_INFO_LIST_REQUEST_TAG_LIST_DEFAULT { false, false, false, false, false, false, false, false, false, false, false, false, false }
#ifdef SGP32
#define CONFIGURE_IMMEDIATE_PROFILE_ENABLING_REQUEST_INITIALIZER { NULL, 0, NULL, 0, { false, false, false} }
#endif

/** ServerSigned1 */
typedef struct server_signed_1_s {
    transaction_id_t transaction_id;
    challenge_t euicc_challenge;
    fqdn_t server_address;
    challenge_t server_challenge;
} server_signed_1_t;

/** SmdpSigned2 */
typedef struct smdp_signed_2_data_presence_s {
    bool bpp_euicc_ot_pk;
} smdp_signed_2_data_presence_t;

typedef struct smdp_signed_2_s {
    transaction_id_t transaction_id;
    bool cc_required_flag;
    const uint8_t *bpp_euicc_ot_pk;
    uint32_t bpp_euicc_ot_pk_size;
    smdp_signed_2_data_presence_t field_is_present;
} smdp_signed_2_t;

// EuiccConfiguredAddressesResponse
typedef struct euicc_configured_addresses_response_data_presence_s {
    bool default_dp_address;
} euicc_configured_addresses_response_data_presence_t;

typedef struct euicc_configured_addresses_response_s {
    fqdn_t default_dp_address;
    fqdn_t root_ds_address;
    euicc_configured_addresses_response_data_presence_t field_is_present;
} euicc_configured_addresses_response_t;

// GetEuiccChallengeResponse
typedef struct get_euicc_challenge_response_s {
    challenge_t euicc_challenge;
} get_euicc_challenge_response_t;

/** EuiccMemoryReset */
// EuiccMemoryResetRequest
typedef struct euicc_memory_reset_request_s {
    bool delete_operational_profiles;
    bool delete_field_loaded_test_profiles;
    bool reset_default_smdp_address;
#ifdef SGP32
    bool delete_preloaded_test_profiles;
    bool delete_provisioning_profiles;
    bool reset_eim_config_data;
    bool reset_immediate_enable_config;
#endif
} euicc_memory_reset_request_t;

// EuiccMemoryResetResponse
typedef enum reset_result_e {
    RESET_RESULT_OK = 0,
    RESET_RESULT_NOTHING_TO_DELETE = 1,
    RESET_RESULT_CAT_BUSY = 5,
#ifdef SGP32
    RESET_RESULT_ECALL_ACTIVE = 104,
#endif
    RESET_RESULT_UNDEFINED_ERROR = 127,
} reset_result_t;

#ifdef SGP32
typedef enum reset_eim_result_e {
    RESET_EIM_RESULT_OK = 0,
    RESET_EIM_RESULT_NOTHING_TO_DELETE = 1,
    RESET_EIM_RESULT_EIM_RESET_NOT_SUPPORTED = 2,
    RESET_EIM_RESULT_UNDEFINED_ERROR = 127,
} reset_eim_result_t;

typedef enum reset_immediate_enable_config_result_e {
    RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_OK = 0,
    RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_IEC_NOT_SUPPORTED = 1,
    RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_UNDEFINED_ERROR = 127,
} reset_immediate_enable_config_result_t;

typedef struct euicc_memory_reset_response_data_presence_s {
    bool reset_eim_result;
    bool reset_immediate_enable_config_result;
} euicc_memory_reset_response_data_presence_t;
#endif

typedef struct euicc_memory_reset_response_s {
    reset_result_t reset_result;
#ifdef SGP32
    reset_eim_result_t reset_eim_result;
    reset_immediate_enable_config_result_t reset_immediate_enable_config_result;
    euicc_memory_reset_response_data_presence_t field_is_present;
#endif
} euicc_memory_reset_response_t;

// AuthenticatServerRequest
typedef struct ctx_params_for_common_authentication_data_presence_s {
    bool matching_id;
} ctx_params_for_common_authentication_data_presence_t;

typedef struct ctx_params_for_common_authentication_s {
    const uint8_t *matching_id;
    uint8_t matching_id_size;
    device_info_t *device_info;
    ctx_params_for_common_authentication_data_presence_t field_is_present;
} ctx_params_for_common_authentication_t;

typedef struct ctx_params_1_s {
    ctx_params_for_common_authentication_t ctx_params_for_common_authentication;
} ctx_params_1_t;

typedef struct ctx_params_1_plain_s {
    uint8_t *data;
    uint16_t size;
} ctx_params_1_plain_t;

typedef union authenticate_server_request_ctx_params_1_value_s {
    ctx_params_1_t ctx_params_1_obj;
    ctx_params_1_plain_t ctx_params_1_plain_value;
} authenticate_server_request_ctx_params_1_value_t;

typedef enum authenticate_server_request_ctx_params_1_type_s {
    CTX_PARAMS_1_OBJ,
    CTX_PARAMS_1_PLAIN
} authenticate_server_request_ctx_params_1_type_t;

typedef struct authenticate_server_request_ctx_params_1_s {
    authenticate_server_request_ctx_params_1_type_t type;
    authenticate_server_request_ctx_params_1_value_t value;
} authenticate_server_request_ctx_params_1_t;

typedef struct authenticate_server_request_s {
    uint8_t *server_signed_1; /* Main TAG included */
    uint32_t server_signed_1_size;
    uint8_t *server_signature_1; /* Main TAG included */
    uint8_t server_signature_1_size;
    uint8_t *server_certificate; /* Main TAG included */
    uint32_t server_certificate_size;
    subject_key_identifier_t euicc_ci_pk_id_to_be_used;
    authenticate_server_request_ctx_params_1_t ctx_params_1;
} authenticate_server_request_t;

// PrepareDownloadRequest
typedef struct prepare_download_request_data_presence_s {
    bool hash_cc;
} prepare_download_request_data_presence_t;

typedef struct prepare_download_request_s {
    const uint8_t *smdp_signed_2; /* Main TAG included */
    uint32_t smdp_signed_2_size;
    const uint8_t *smdp_signature_2; /* Main TAG included */
    uint32_t smdp_signature_2_size;
    sha256_hash_t hash_cc;
    const uint8_t *smdp_certificate; /* Main TAG included */
    uint32_t smdp_certificate_size;
    prepare_download_request_data_presence_t field_is_present;
} prepare_download_request_t;

/* Bound Profile Package */
typedef struct bound_profile_package_data_presence_s {
    bool second_sequence_of_87;
} bound_profile_package_data_presence_t;

typedef struct bound_profile_package_s {
    uint8_t *initialise_secure_channel_request;
    uint32_t initialise_secure_channel_request_size;
    uint8_t *first_sequence_of_87;
    uint32_t first_sequence_of_87_size;
    asn1_list_iterator_t sequence_of_88;
    uint8_t *second_sequence_of_87;
    uint32_t second_sequence_of_87_size;
    asn1_list_iterator_t sequence_of_86;
    bound_profile_package_data_presence_t field_is_present;
} bound_profile_package_t;

/* Initialise Secure Channel Request */
typedef struct initialise_secure_channel_request_s {
    uint8_t remote_op_id;
    transaction_id_t transaction_id;
    uint8_t *control_ref_template;
    uint32_t control_ref_template_size;
    uint8_t *smdp_otpk;
    uint32_t smdp_otpk_size;
    uint8_t *smdp_sign;
    uint32_t smdp_sign_size;
} initialise_secure_channel_request_t;

/* Segmented Bound Profile Package */
typedef struct segmented_bound_profile_package_data_presence_s {
    bool second_sequence_of_87;
} segmented_bound_profile_package_data_presence_t;

typedef struct segmented_bound_profile_package_s {
    const uint8_t *tag_length_bpp_and_init_secure_channel_req;   /* Tag and length fields of the BoundProfilePackage TLV plus the initialiseSecureChannelRequest TLV */
    uint32_t tag_length_bpp_and_init_secure_channel_req_size;
    const uint8_t *first_sequence_of_87;         /* Tag and length fields of the first sequenceOf87 TLV plus the first '87' TLV */
    uint32_t first_sequence_of_87_size;
    const uint8_t *tag_length_sequence_of_88;    /* Tag and length fields of the sequenceOf88 TLV */
    uint8_t tag_length_sequence_of_88_size;
    asn1_list_iterator_t elements_of_88;      /* Each of the '88' TLVs */
    const uint8_t *second_sequence_of_87;        /* Tag and length fields of the sequenceOf87 TLV plus the first '87' TLV */
    uint32_t second_sequence_of_87_size;
    const uint8_t *tag_length_sequence_of_86;    /* Tag and length fields of the sequenceOf86 TLV */
    uint8_t tag_length_sequence_of_86_size;
    asn1_list_iterator_t elements_of_86;      /* Each of the '86' TLVs */
    segmented_bound_profile_package_data_presence_t field_is_present;
} segmented_bound_profile_package_t;

// NotificationMetadata
typedef enum notification_event_e {
    NOTIFICATION_EVENT_INSTALL = 0,
    NOTIFICATION_EVENT_ENABLE = 1,
    NOTIFICATION_EVENT_DISABLE = 2,
    NOTIFICATION_EVENT_DELETE = 3
} notification_event_t;

typedef struct notification_metadata_data_presence_s {
    bool iccid;
} notification_metadata_data_presence_t;

typedef struct notification_metadata_s {
    uint32_t seq_number;
    notification_event_t profile_management_operation;
    fqdn_t notification_address;
    iccid_t iccid;
    notification_metadata_data_presence_t field_is_present;
} notification_metadata_t;

// ProfileDownloadTriggerResult
typedef enum final_result_choice_e {
    FINAL_RESULT_CHOICE_SUCCESS_RESULT,
    FINAL_RESULT_CHOICE_ERROR_RESULT
} final_result_choice_t;

typedef struct success_result_s {
    uint8_t aid[16];
    uint8_t aid_size; // SIZE (5..16)
    const uint8_t *sima_response;
    uint32_t sima_response_size;
} success_result_t;

typedef enum bpp_command_id_e {
    BPP_COMMAND_ID_INITIALISE_SECURE_CHANNEL = 0,
    BPP_COMMAND_ID_CONFIGURE_ISDP = 1,
    BPP_COMMAND_ID_STORE_METADATA = 2,
    BPP_COMMAND_ID_STORE_METADATA_2 = 3,
    BPP_COMMAND_ID_REPLACE_SESSION_KEYS = 4,
    BPP_COMMAND_ID_LOAD_PROFILE_ELEMENTS = 5
} bpp_command_id_t;

typedef enum error_reason_e {
    INCORRECT_INPUT_VALUES = 1,
    INVALID_SIGNATURE = 2,
    INVALID_TRANSACTION_ID = 3,
    UNSUPPORTED_CRT_VALUES = 4,
    UNSUPPORTED_REMOTE_OPERATION_TYPE = 5,
    UNSUPPORTED_PROFILE_CLASS = 6,
    SCP03T_STRUCTURE_ERROR = 7,
    SCP03T_SECURITY_ERROR = 8,
    INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC = 9,
    INSTALL_FAILED_DUE_TO_INSUFFICIENT_MEMORY_FOR_PROFILE = 10,
    INSTALL_FAILED_DUE_TO_INTERRUPTION = 11,
    INSTALL_FAILED_DUE_TO_PE_PROCESSING_ERROR = 12,
    INSTALL_FAILED_DUE_TO_DATA_MISMATCH = 13,
    TEST_PROFILE_INSTALL_FAILED_DUE_TO_INVALID_NAA_KEY = 14,
    PPR_NOT_ALLOWED = 15,
    INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR = 127
} error_reason_t;

typedef struct error_result_data_presence_s {
    bool sima_response;
} error_result_data_presence_t;

typedef struct error_result_s {
    bpp_command_id_t bpp_command_id;
    error_reason_t error_reason;
    const uint8_t *sima_response;
    uint32_t sima_response_size;
    error_result_data_presence_t field_is_present;
} error_result_t;

typedef union final_result_value_u {
    success_result_t success_result;
    error_result_t error_result;
} final_result_value_t;

typedef struct final_result_s {
    final_result_choice_t choice;
    final_result_value_t value;
} final_result_t;

typedef struct profile_installation_result_data_s {
    transaction_id_t transaction_id;
    notification_metadata_t notification_metadata;
    const uint8_t *smdp_oid;
    uint32_t smdp_oid_size;
    final_result_t final_result;
} profile_installation_result_data_t;

typedef struct profile_installation_result_s {
    profile_installation_result_data_t profile_installation_result_data;
    const uint8_t *euicc_sign_pir;
    uint32_t euicc_sign_pir_size;
} profile_installation_result_t;

// CancelSessionRequest
typedef enum cancel_session_reason_e {
    CANCEL_SESSION_REASON_END_USER_REJECTION = 0,
    CANCEL_SESSION_REASON_POSTPONED = 1,
    CANCEL_SESSION_REASON_TIMEOUT = 2,
    CANCEL_SESSION_REASON_PPR_NOT_ALLOWED = 3,
    CANCEL_SESSION_REASON_METADATA_MISMATCH = 4,
    CANCEL_SESSION_REASON_LOAD_BPP_EXECUTION_ERROR = 5,
    CANCEL_SESSION_REASON_UNDEFINED_REASON = 127
} cancel_session_reason_t;

typedef struct cancel_session_request_s {
    transaction_id_t transaction_id;
    cancel_session_reason_t reason;
} cancel_session_request_t;

// RetrieveNotificationsListRequest
typedef enum retrieve_notifications_list_request_search_criteria_choice_e {
    SEQ_NUMBER_CHOICE,
    PROFILE_MANAGEMENT_OPERATION_CHOICE,
#ifdef SGP32
    EUICC_PACKAGE_RESULTS_CHOICE
#endif
} retrieve_notifications_list_request_search_criteria_choice_t;

typedef union retrieve_notifications_list_request_search_criteria_choice_value_u {
    uint32_t seq_number;
    notification_event_t profile_management_operation;
} retrieve_notifications_list_request_search_criteria_choice_value_t;

typedef struct retrieve_notifications_list_request_search_criteria_s {
    retrieve_notifications_list_request_search_criteria_choice_value_t value;
    retrieve_notifications_list_request_search_criteria_choice_t choice;      // CHOICE of the search criteria
} retrieve_notifications_list_request_search_criteria_t;

typedef struct retrieve_notifications_list_request_data_presence_s {
    bool search_criteria;                                                   // Indicates if the searchCriteria field is present or not
} retrieve_notifications_list_request_data_presence_t;

typedef struct retrieve_notifications_list_request_s {
    retrieve_notifications_list_request_search_criteria_t search_criteria;  // If search_criteria field is present, represents its value
    retrieve_notifications_list_request_data_presence_t field_is_present;   // Indicates which of the optional fields are present and which are not
} retrieve_notifications_list_request_t;

// RetrieveNotificationsListResponse
typedef enum notifications_list_result_error_e {
    NOTIFICATIONS_LIST_RESULT_ERROR_UNDEFINED_ERROR = 127
} notifications_list_result_error_t;

typedef enum retrieve_notifications_list_response_choice_e {
    NOTIFICATIONS_LIST_CHOICE,
    NOTIFICATIONS_LIST_RESULT_ERROR_CHOICE,
#ifdef SGP32
    EUICC_PACKAGE_RESULT_LIST_CHOICE,
#endif
} retrieve_notifications_list_response_choice_t;

typedef union retrieve_notifications_list_response_value_u {
    asn1_list_iterator_t notification_list;
    notifications_list_result_error_t notifications_list_result_error;
#ifdef SGP32
    asn1_list_iterator_t euicc_package_result_list;
#endif
} retrieve_notifications_list_response_value_t;

typedef struct retrieve_notifications_list_response_s {
    retrieve_notifications_list_response_choice_t choice;
    retrieve_notifications_list_response_value_t value;
} retrieve_notifications_list_response_t;

// NotificationSentRequest
typedef struct notification_sent_request_s {
    uint32_t seq_number;
} notification_sent_request_t;

// NotificationSentResponse
typedef enum delete_notification_status_e {
    DELETE_NOTIFICATION_STATUS_OK = 0,
    DELETE_NOTIFICATION_STATUS_NOTHING_TO_DELETE = 1,
    DELETE_NOTIFICATION_STATUS_UNDEFINED_ERROR = 127,
} delete_notification_status_t;

typedef struct notification_sent_response_s {
    delete_notification_status_t delete_notification_status;
} notification_sent_response_t;

/** GetRAT */
typedef struct ppr_ids_s {
    bool ppr_update_control; // defines how to update PPRs via ES6
    bool ppr1; // Indicator for PPR1 'Disabling of this Profile is not allowed'
    bool ppr2; // Indicator for PPR2 'Deletion of this Profile is not allowed'
} ppr_ids_t;

typedef struct ppr_flags_s {
    bool consent_required;
} ppr_flags_t;

typedef struct profile_policy_authorisation_rule_s {
    ppr_ids_t ppr_ids;
    asn1_list_iterator_t allowed_operators; // SEQUENCE OF OperatorId
    ppr_flags_t ppr_flags;
} profile_policy_authorisation_rule_t;

typedef struct get_rat_response_s {
    asn1_list_iterator_t rat; // SEQUENCE OF ProfilePolicyAuthorisationRule
} get_rat_response_t;

/** GetProfilesInfo */
// ProfileInfoListRequest
typedef enum profile_class_s {
    PROFILE_CLASS_TEST = 0,
    PROFILE_CLASS_PROVISIONING = 1,
    PROFILE_CLASS_OPERATIONAL = 2
} profile_class_t;

typedef enum profile_info_list_request_serach_criteria_choice_s {
    ISDP_AID_PROFILE_INFO_LIST_CHOICE,
    ICCID_PROFILE_INFO_LIST_CHOICE,
    PROFILE_CLASS_PROFILE_INFO_LIST_CHOICE
} profile_info_list_request_serach_criteria_choice_t;

typedef union profile_info_list_request_serach_criteria_value_s {
    isdp_aid_t isdp_aid;
    iccid_t iccid;
    profile_class_t profile_class;
} profile_info_list_request_serach_criteria_value_t;

typedef struct profile_info_list_request_serach_criteria_s {
    profile_info_list_request_serach_criteria_choice_t choice;
    profile_info_list_request_serach_criteria_value_t value;
} profile_info_list_request_serach_criteria_t;

typedef struct profile_info_list_request_tag_list_s {
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
    bool smdp_propietary_data;
    bool profile_policy_rules;
    // bool service_specific_data_stored_in_euicc; Introduced in SGP.22 2.5.0
#ifdef SGP32
    bool ecall_indication;
    bool fallback_attribute;
    bool fallback_allowed;
#endif
} profile_info_list_request_tag_list_t;

typedef struct profile_info_list_request_data_presence_s {
    bool search_criteria;
    bool tag_list;
} profile_info_list_request_data_presence_t;

typedef struct profile_info_list_request_s {
    profile_info_list_request_serach_criteria_t search_criteria;
    profile_info_list_request_tag_list_t tag_list;
    profile_info_list_request_data_presence_t field_is_present;
} profile_info_list_request_t;

// ProfileInfoListResponse
typedef enum profile_info_list_error_e {
    PROFILE_INFO_LIST_ERROR_INCORRECT_INPUT_VALUES = 1,
    PROFILE_INFO_LIST_ERROR_UNDEFINED_ERROR = 127
} profile_info_list_error_t;

typedef enum profile_info_list_response_choice_e {
    PROFILE_INFO_LIST_OK_CHOICE,
    PROFILE_INFO_LIST_ERROR_CHOICE
} profile_info_list_response_choice_t;

typedef union profile_info_list_response_value_u {
    asn1_list_iterator_t ok;
    profile_info_list_error_t error;
} profile_info_list_response_value_t;

typedef struct profile_info_list_response_s {
    profile_info_list_response_choice_t choice;
    profile_info_list_response_value_t value;
} profile_info_list_response_t;

// ProfileInfo
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

typedef enum icon_type_e {
    ICON_TYPE_JPG = 0,
    ICON_TYPE_PNG = 1,
} icon_type_t;

typedef struct icon_s {
    uint8_t value[ICON_OCTET_STRING_MAX_SIZE];
    uint16_t size;
} icon_t;

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

typedef struct dp_propietary_data_s {   // This structure may have other propietary data
    uint8_t dp_oid[DP_PROPIETARY_DATA_MAX_SIZE];
    uint8_t dp_oid_size;
} dp_propietary_data_t;

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
    // bool service_specific_data_stored_in_euicc; Introduced in SGP.22 2.5.0
#ifdef SGP32
    bool ecall_indication;
    bool fallback_attribute;
    bool fallback_allowed;
#endif
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
    // service_specific_data_stored_in_euicc_t service_specific_data_stored_in_euicc; Introduced in SGP.22 2.5.0
#ifdef SGP32
    bool ecall_indication;
    bool fallback_attribute;
    bool fallback_allowed;
#endif
    profile_info_data_presence_t field_is_present;
} profile_info_t;

typedef struct notification_configuration_information_s {
    notification_event_t profile_management_operation;
    fqdn_t notification_address;
} notification_configuration_information_t;

// GetEuiccDataResponse
typedef struct get_euicc_data_response_s {
    eid_t eid_value;
} get_euicc_data_response_t;

// SetDefaultDpAddressRequest
typedef struct set_default_dp_address_request_s {
    unsigned char *default_dp_address; // Should we assign here a buffer of 256?. Max len of FQDN is 255...
    uint32_t default_dp_address_len;
} set_default_dp_address_request_t;

// SetDefaultDpAddressResponse
typedef enum set_default_dp_address_result_e {
    SET_DEFAULT_DP_ADDRESS_RESULT_OK = 0,
    SET_DEFAULT_DP_ADDRESS_RESULT_UNDEFINED_ERROR = 127
} set_default_dp_address_result_t;

typedef struct set_default_dp_address_response_s {
    set_default_dp_address_result_t set_default_dp_address_result;
} set_default_dp_address_response_t;

#ifdef SGP22
// ListNotificationRequest
typedef struct list_notification_request_data_presences {
    bool profile_management_operation;
} list_notification_request_data_presence_t;

typedef struct list_notification_request_s {
    notification_event_t profile_management_operation;
    list_notification_request_data_presence_t field_is_present;
} list_notification_request_t;

// ListNotificationResponse
typedef enum list_notification_response_choice_e {
    NOTIFICATION_METADATA_LIST_CHOICE,
    LIST_NOTIFICATION_RESULTS_ERROR_CHOICE
} list_notification_response_choice_t;

typedef union list_notification_response_value_u {
    asn1_list_iterator_t notification_metadata_list;
    notifications_list_result_error_t list_notifications_result_error;
} list_notification_response_value_t;

typedef struct list_notification_response_s {
    list_notification_response_choice_t choice;
    list_notification_response_value_t value;
} list_notification_response_t;

// EnableProfileRequest/DisableProfileRequest
typedef union profile_identifier_value_s {
    isdp_aid_t isdp_aid;
    iccid_t iccid;
} profile_identifier_value_t;

typedef enum profile_identifier_choice_s {
    ISDP_AID_PROFILE_IDENTIFIER_CHOICE,
    ICCID_PROFILE_IDENTIFIER_CHOICE
} profile_identifier_choice_t;

typedef struct profile_identifier_s {
    profile_identifier_choice_t choice;
    profile_identifier_value_t value;
} profile_identifier_t;

typedef struct profile_state_change_request_s {
    profile_identifier_t profile_identifier;
    bool refresh_flag;
} profile_state_change_request_t;

// EnableProfileRequest
typedef profile_state_change_request_t enable_profile_request_t;

// EnableProfileResponse
typedef enum enable_result_e {
    ENABLE_RESULT_OK = 0,
    ENABLE_RESULT_ICCID_OR_AID_NOT_FOUND = 1,
    ENABLE_RESULT_PROFILE_NOT_IN_DISABLED_STATE = 2,
    ENABLE_RESULT_DISALLOWED_BY_POLICY = 3,
    ENABLE_RESULT_WRONG_PROFILE_REENABLING = 4,
    ENABLE_RESULT_CAT_BUSY = 5,
    ENABLE_RESULT_UNDEFINED_ERROR = 127
} enable_result_t;

typedef struct enable_profile_response_s {
    enable_result_t enable_result;
} enable_profile_response_t;

// DisableProfileRequest
typedef profile_state_change_request_t disable_profile_request_t;

// DisableProfileResponse
typedef enum disable_result_e {
    DISABLE_RESULT_OK = 0,
    DISABLE_RESULT_ICCID_OR_AID_NOT_FOUND = 1,
    DISABLE_RESULT_PROFILE_NOT_IN_ENABLED_STATE = 2,
    DISABLE_RESULT_DISALLOWED_BY_POLICY = 3,
    DISABLE_RESULT_CAT_BUSY = 5,
    DISABLE_RESULT_UNDEFINED_ERROR = 127
} disable_result_t;

typedef struct disable_profile_response_s {
    disable_result_t disable_result;
} disable_profile_response_t;

// DeleteProfileRequest
typedef profile_identifier_t delete_profile_request_t;

// DeleteProfileResponse
typedef enum delete_result_e {
    DELETE_RESULT_OK = 0,
    DELETE_RESULT_ICCID_OR_AID_NOT_FOUND = 1,
    DELETE_RESULT_PROFILE_NOT_IN_DISABLED_STATE = 2,
    DELETE_RESULT_DISALLOWED_BY_POLICY = 3,
    DELETE_RESULT_UNDEFINED_ERROR = 127
} delete_result_t;

typedef struct delete_profile_response_s {
    delete_result_t delete_result;
} delete_profile_response_t;

// SetNicknameRequest
typedef struct set_nickname_request_s{
    iccid_t iccid;
    profile_nickname_t profile_nickname;
} set_nickname_request_t;

// SetNicknameResponse
typedef enum set_nickname_result_e {
    SET_NICKNAME_RESULT_OK = 0,
    SET_NICKNAME_RESULT_ICCID_NOT_FOUND = 1,
    SET_NICKNAME_RESULT_UNDEFINED_ERROR = 127
} set_nickname_result_t;

typedef struct set_nickname_response_s {
    set_nickname_result_t set_nickname_result;
} set_nickname_response_t;
#endif

#ifdef SGP32
// EuiccPackageResult
typedef struct euicc_package_result_data_signed_data_presence_s {
    bool eim_transaction_id;
} euicc_package_result_data_signed_data_presence_t;

typedef struct euicc_package_result_data_signed_s {
    uint8_t *eim_id;
    uint8_t eim_id_size;
    uint32_t counter_value;
    transaction_id_t eim_transaction_id;
    uint32_t seq_number;
    asn1_list_iterator_t euicc_result;
    euicc_package_result_data_signed_data_presence_t field_is_present;
} euicc_package_result_data_signed_t;

typedef struct euicc_package_result_signed_s {
    euicc_package_result_data_signed_t euicc_package_result_data_signed;
    uint8_t *euicc_sign_epr;
    uint32_t euicc_sign_epr_size;
} euicc_package_result_signed_t;

typedef struct euicc_package_error_data_signed_data_presence_s {
    bool eim_transaction_id;
} euicc_package_error_data_signed_data_presence_t;

typedef enum euicc_package_error_code_e {
    EUICC_PACKAGE_ERROR_CODE_INVALID_EID = 3,
    EUICC_PACKAGE_ERROR_CODE_REPLAY_ERROR = 4,
    EUICC_PACKAGE_ERROR_CODE_COUNTER_VALUE_OUT_OF_RANGE = 6,
    EUICC_PACKAGE_ERROR_CODE_SIZE_OVERFLOW = 15,
    EUICC_PACKAGE_ERROR_CODE_ECALL_ACTIVE = 104,
    EUICC_PACKAGE_ERROR_CODE_UNDEFINED_ERROR = 127
} euicc_package_error_code_t;

typedef struct euicc_package_error_data_signed_s {
    uint8_t *eim_id;
    uint8_t eim_id_size;
    uint32_t counter_value;
    transaction_id_t eim_transaction_id;
    euicc_package_error_code_t euicc_package_error_code;
    euicc_package_error_data_signed_data_presence_t field_is_present;
} euicc_package_error_data_signed_t;

typedef struct euicc_package_error_signed_s {
    euicc_package_error_data_signed_t euicc_package_error_data_signed;
    uint8_t *euicc_sign_epe;
    uint32_t euicc_sign_epe_size;
} euicc_package_error_signed_t;

typedef struct euicc_package_error_unsigned_data_presence_s {
    bool eim_transaction_id;
    bool association_token;
} euicc_package_error_unsigned_data_presence_t;

typedef struct euicc_package_error_unsigned_s {
    uint8_t *eim_id;
    uint8_t eim_id_size;
    transaction_id_t eim_transaction_id;
    uint32_t association_token;
    euicc_package_error_unsigned_data_presence_t field_is_present;
} euicc_package_error_unsigned_t;

typedef union euicc_package_result_choice_value_u {
    euicc_package_result_signed_t euicc_package_result_signed;
    euicc_package_error_signed_t euicc_package_error_signed;
    euicc_package_error_unsigned_t euicc_package_error_unsigned;
} euicc_package_result_choice_value_t;

typedef enum euicc_package_result_choice_e {
    EUICC_PACKAGE_RESULT_SIGNED_CHOICE,
    EUICC_PACKAGE_ERROR_SIGNED_CHOICE,
    EUICC_PACKAGE_ERROR_UNSIGNED_CHOICE
} euicc_package_result_choice_t;

typedef struct euicc_package_result_s {
    euicc_package_result_choice_t choice;
    euicc_package_result_choice_value_t value;
} euicc_package_result_t;

// EimConfigurationData
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

typedef struct get_eim_configuration_data_response_s {
    asn1_list_iterator_t eim_configuration_data_list_iterator;
} get_eim_configuration_data_response_t;

// AddInitialEimResponse
typedef enum add_initial_eim_error_e {
    ADD_INITIAL_EIM_ERROR_INSUFFICIENT_MEMORY = 1,
    ADD_INITIAL_EIM_ERROR_ASSOCIATED_EIM_ALREADY_EXISTS = 2,
    ADD_INITIAL_EIM_ERROR_CI_PK_UNKNOWN = 3,
    ADD_INITIAL_EIM_ERROR_INVALID_ASSOCIATION_TOKEN = 5,
    ADD_INITIAL_EIM_ERROR_COUNTER_VALUE_OUT_OF_RANGE = 6,
    ADD_INITIAL_EIM_ERROR_COMMAND_ERROR = 7,
    ADD_INITIAL_EIM_ERROR_UNDEFINED_ERROR = 127
} add_initial_eim_error_t;

typedef enum add_initial_eim_ok_choice_e {
    ASSOCATION_TOKEN_CHOICE,
    ADD_OK_CHOICE
} add_initial_eim_ok_choice_t;

typedef union add_initial_eim_ok_choice_value_u {
    uint32_t assocation_token;
} add_initial_eim_ok_choice_value_t;

typedef struct add_initial_eim_ok_s {
    add_initial_eim_ok_choice_t choice;
    add_initial_eim_ok_choice_value_t value;
} add_initial_eim_ok_t;

typedef enum add_initial_eim_response_choice_e {
    ADD_INITIAL_EIM_OK_CHOICE,
    ADD_INITIAL_EIM_ERROR_CHOICE
} add_initial_eim_response_choice_t;

typedef union add_initial_eim_response_choice_value_u {
    add_initial_eim_ok_t add_initial_eim_ok;
    add_initial_eim_error_t add_initial_eim_error;
} add_initial_eim_response_choice_value_t;

typedef struct add_initial_eim_response_s {
    add_initial_eim_response_choice_t choice;
    add_initial_eim_response_choice_value_t value;
} add_initial_eim_response_t;

/** GetCerts */
// GetCertsRequest
typedef struct get_certs_request_data_presence_s {
    bool euicc_ci_pk_id;
} get_certs_request_data_presence_t;

typedef struct get_certs_request_s {
    subject_key_identifier_t euicc_ci_pk_id;
    get_certs_request_data_presence_t field_is_present;
} get_certs_request_t;

// GetCertsResponse
typedef enum get_certs_response_choice_e {
    CERTS_CHOICE,
    GET_CERTS_ERROR_CHOICE
} get_certs_response_choice_t;

typedef enum get_certs_error_e {
    GET_CERTS_ERROR_INVALID_CI_PK_ID = 1,
    GET_CERTS_ERROR_UNDEFINED_ERROR = 127
} get_certs_error_t;

typedef struct certs_s {
    uint8_t *eum_certificate;
    uint16_t eum_certificate_size;
    uint8_t *euicc_certificate;
    uint16_t euicc_certificate_size;
} certs_t;

typedef union get_certs_response_choice_value_u {
    certs_t certs;
    get_certs_error_t get_certs_error;
} get_certs_response_choice_value_t;

typedef struct get_certs_response_s {
    get_certs_response_choice_t choice;
    get_certs_response_choice_value_t value;
} get_certs_response_t;

/** ImmediateEnable */
// ImmediateEnablRequest
typedef struct immediate_enable_request_s {
    bool refresh_flag;
} immediate_enable_request_t;

// ImmediateEnablResponse
typedef enum immediate_enable_result_e {
    IMMEDIATE_ENABLE_RESULT_OK = 0,
    IMMEDIATE_ENABLE_RESULT_IMMEDIATE_ENABLE_NOT_AVAILABLE = 1,
    IMMEDIATE_ENABLE_RESULT_NO_SESSION_CONTEXT = 4,
    IMMEDIATE_ENABLE_RESULT_CAT_BUSY = 5,
    IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR = 127,
} immediate_enable_result_t;

typedef struct immediate_enable_response_s {
    immediate_enable_result_t immediate_enable_result;
} immediate_enable_response_t;

/** ProfileRollback */
// ProfileRollbackRequest
typedef struct profile_rollback_request_s {
    bool refresh_flag;
} profile_rollback_request_t;

// ProfileRollbackResponse
typedef enum profile_rollback_result_e {
    PROFILE_ROLLBACK_RESULT_OK = 0,
    PROFILE_ROLLBACK_RESULT_ROLLBACK_NOT_ALLOWED = 1,
    PROFILE_ROLLBACK_RESULT_CAT_BUSY = 5,
    PROFILE_ROLLBACK_RESULT_COMMAND_ERROR = 7,
    PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR = 127
} profile_rollback_result_t;

typedef struct profile_rollback_response_s {
    profile_rollback_result_t cmd_result;
    uint8_t *euicc_package_result;      // Null if eUICCPackageResult is not present
    uint32_t euicc_package_result_size; // 0 if eUICCPackageResult is not present
} profile_rollback_response_t;

/** ConfigureImmediateProfileEnabling */
typedef struct {
    const char *smdp_oid;
    const char *smdp_address;
    bool immediate_enable_flag;
} profile_enabling_config_t;
// ConfigureImmediateProfileEnablingRequest
typedef struct configure_immediate_profile_enabling_request_data_presence_s {
    bool immediate_enable_flag;
    bool default_smdp_oid;
    bool default_smdp_address;
} configure_immediate_profile_enabling_request_data_presence_t;

typedef struct configure_immediate_profile_enabling_request_s {
    unsigned char *default_smdp_oid;
    uint32_t default_smdp_oid_len;
    unsigned char *default_smdp_address;
    uint32_t default_smdp_address_len;
    configure_immediate_profile_enabling_request_data_presence_t field_is_present;
} configure_immediate_profile_enabling_request_t;

// ConfigureImmediateProfileEnablingResponse
typedef enum config_immediate_enable_result_e {
    CONFIG_IMMEDIATE_ENABLE_RESULT_OK = 0,
    CONFIG_IMMEDIATE_ENABLE_RESULT_INSUFFICIENT_MEMORY = 1,
    CONFIG_IMMEDIATE_ENABLE_RESULT_ASSOCIATED_EIM_ALREADY_EXISTS = 2,
    CONFIG_IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR = 127
} config_immediate_enable_result_t;

typedef struct configure_immediate_profile_enabling_response_s {
    config_immediate_enable_result_t config_immediate_enable_result;
} configure_immediate_profile_enabling_response_t;

// GetEimConfigurationData
typedef struct eim_id_s {
    unsigned char value[EIM_ID_MAX_SIZE];
    uint8_t len;
} eim_id_t;

typedef union get_eim_configuration_data_request_search_criteria_choice_value_u {
    eim_id_t eim_id;
} get_eim_configuration_data_request_search_criteria_choice_value_t;

// GetEimConfigurationDataRequest
typedef enum get_eim_configuration_data_request_search_criteria_choice_e {
    EIM_ID
} get_eim_configuration_data_request_search_criteria_choice_t;

typedef struct get_eim_configuration_data_request_search_criteria_s {
    get_eim_configuration_data_request_search_criteria_choice_value_t value;
    get_eim_configuration_data_request_search_criteria_choice_t choice;      // CHOICE of the search criteria
} get_eim_configuration_data_request_search_criteria_t;

typedef struct get_eim_configuration_data_request_data_presence_s {
    bool search_criteria;                                                   // Indicates if the searchCriteria field is present or not
} get_eim_configuration_data_request_data_presence_t;

typedef struct get_eim_configuration_data_request_e {
    get_eim_configuration_data_request_search_criteria_t search_criteria;   // If search_criteria field is present, represents its value   
    get_eim_configuration_data_request_data_presence_t field_is_present;    // Indicates which of the optional fields are present and which are not
} get_eim_configuration_data_request_t;

// Emergency profile
#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
typedef struct emergency_profile_request_s {
    bool refresh_flag;
} enable_emergency_profile_request_t, disable_emergency_profile_request_t;

typedef enum enable_emergency_profile_result_e {
    ENABLE_EMERGENCY_PROFILE_RESULT_OK = 0,
    ENABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_DISABLED_STATE = 2,
    ENABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY = 5,
    ENABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE = 8,
    ENABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR = 127
} enable_emergency_profile_result_t;

typedef enum disable_emergency_profile_result_e {
    DISABLE_EMERGENCY_PROFILE_RESULT_OK = 0,
    DISABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_ENABLED_STATE = 2,
    DISABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY = 5,
#ifdef PRE_CR
    DISABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE = 8,
#endif
    DISABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR = 127
} disable_emergency_profile_result_t;

typedef struct enable_emergency_profile_response_s {
    enable_emergency_profile_result_t enable_emergency_profile_result;
} enable_emergency_profile_response_t;

typedef struct disable_emergency_profile_response_s {
    disable_emergency_profile_result_t disable_emergency_profile_result;
} disable_emergency_profile_response_t;
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
/* ExecuteFallbackMechanism */
// ExecuteFallbackMechanismRequest
typedef struct execute_fallback_mechanism_request_s {
    bool refresh_flag;
} execute_fallback_mechanism_request_t;

// ExecuteFallbackMechanismResponse
typedef enum execute_fallback_mechanism_result_e {
    EXECUTE_FALLBACK_MECHANISM_RESULT_OK = 0,
    EXECUTE_FALLBACK_MECHANISM_RESULT_PROFILE_NOT_IN_DISABLED_STATE = 2,
    EXECUTE_FALLBACK_MECHANISM_RESULT_CAT_BUSY = 5,
    EXECUTE_FALLBACK_MECHANISM_RESULT_FALLBACK_NOT_AVAILABLE = 6,
    EXECUTE_FALLBACK_MECHANISM_RESULT_COMMAND_ERROR = 7,
    EXECUTE_FALLBACK_MECHANISM_RESULT_ECALL_ACTIVE = 104,
    EXECUTE_FALLBACK_MECHANISM_RESULT_UNDEFINED_ERROR = 127
} execute_fallback_mechanism_result_t;

typedef struct execute_fallback_mechanism_response_s {
    execute_fallback_mechanism_result_t execute_fallback_mechanism_result;
} execute_fallback_mechanism_response_t;

/* ReturnFromFallback */
// ReturnFromFallbackRequest
typedef struct return_from_fallback_request_s {
    bool refresh_flag;
} return_from_fallback_request_t;

// ReturnFromFallbackResponse
typedef enum return_from_fallback_result_e {
    RETURN_FROM_FALLBACK_RESULT_OK = 0,
    RETURN_FROM_FALLBACK_RESULT_CAT_BUSY = 5,
    RETURN_FROM_FALLBACK_RESULT_FALLBACK_NOT_AVAILABLE = 6,
    RETURN_FROM_FALLBACK_RESULT_COMMAND_ERROR = 7,
    RETURN_FROM_FALLBACK_RESULT_UNDEFINED_ERROR = 127
} return_from_fallback_result_t;

typedef struct return_from_fallback_response_s {
    return_from_fallback_result_t return_from_fallback_result;
} return_from_fallback_response_t;
#endif
#endif
