/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "ipa_typedefs.h"
#include "es10_typedefs.h"
#include "device_info.h"
#include "tlv_lengths.h"
#include "rsp.h"

/* eIM Package Result */
typedef struct euicc_package_result_esipa_s {
    uint8_t* tlv;
    uint32_t tlv_size;
    euicc_package_result_t obj; 
} euicc_package_result_esipa_t;

// ePRAndNotifications
typedef struct epr_and_notifications_s {
    euicc_package_result_esipa_t euicc_package_result; // SHALL be in the first position, this way the CHOICE ePRAndNotifications can be cast to the CHOICE euiccPackageResult
    void* context_notification_list;
    uint8_t* notification_list;
    uint32_t notification_list_size;
} epr_and_notifications_t;

// IpaEuiccDataResponse
typedef enum ipa_euicc_data_error_code_e {
    IPA_EUICC_DATA_ERROR_INCORRECT_TAG_LIST = 1,
    IPA_EUICC_DATA_ERROR_EUICC_CI_PK_ID_NOT_FOUND = 5,
    IPA_EUICC_DATA_ERROR_ECALL_ACTIVE = 104,
    IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR = 127
} ipa_euicc_data_error_code_t;

typedef struct ipa_euicc_data_response_error_data_presence_s {
    bool eim_transaction_id;
} ipa_euicc_data_response_error_data_presence_t;

typedef struct ipa_euicc_data_response_error_s {
    transaction_id_t eim_transaction_id;
    ipa_euicc_data_error_code_t ipa_euicc_data_error_code;
    ipa_euicc_data_response_error_data_presence_t field_is_present;
} ipa_euicc_data_response_error_t;

typedef struct ipa_euicc_data_presence_s {
    bool notifications_list;
    bool default_smdp_address;
    bool euicc_package_result_list;
    bool euicc_info_1;
    bool euicc_info_2;
    bool root_smds_address;
    bool association_token;
    bool eum_cert;
    bool euicc_cert;
    bool eim_transaction_id;
    bool ipa_capabilities;
    bool device_information;
} ipa_euicc_data_presence_t;

typedef struct ipa_euicc_data_s {
    void* get_certs_context;
    void* retrieve_notifications_list_context;
    void* retrieve_euicc_packages_list_context;
    uint8_t* notifications_list;
    uint32_t notifications_list_size;
    fqdn_t default_smdp_address;
    uint8_t* euicc_package_result_list;
    uint32_t euicc_package_result_list_size;
    uint8_t* euicc_info_1;
    uint32_t euicc_info_1_size;
    uint8_t* euicc_info_2;
    uint32_t euicc_info_2_size;
    fqdn_t root_smds_address;
    uint32_t association_token;
    uint8_t* eum_certificate;
    uint32_t eum_certificate_size;
    uint8_t* euicc_certificate;
    uint32_t euicc_certificate_size;
    transaction_id_t eim_transaction_id;
    ipa_capabilities_t ipa_capabilities;
    device_info_t* device_info;
    ipa_euicc_data_presence_t field_is_present;
} ipa_euicc_data_t;

typedef enum ipa_euicc_data_response_choice_e {
    IPA_EUICC_DATA_CHOICE,
    IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE
} ipa_euicc_data_response_choice_t;

typedef union ipa_euicc_data_response_choice_value_u {
    ipa_euicc_data_t ipa_euicc_data;
    ipa_euicc_data_response_error_t ipa_euicc_data_response_error;
} ipa_euicc_data_response_choice_value_t;

typedef struct ipa_euicc_data_response_s {
    ipa_euicc_data_response_choice_t choice;        // Indicates the CHOICE of the IpaEuiccDataResponse
    ipa_euicc_data_response_choice_value_t value;   // Contain the value of the IpaEuiccDataResponse CHOICE
} ipa_euicc_data_response_t;

// profileDownloadTriggerResult
typedef enum profile_download_error_reason_e {
    PROFILE_DOWNLOAD_ERROR_REASON_ECALL_ACTIVE = 104,
    PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON = 127
} profile_download_error_reason_t;

typedef struct profile_download_error_s {
    profile_download_error_reason_t profile_download_error_reason;
    uint8_t* error_response;           // Can be NULL. This field is optional
    uint32_t error_response_size;
} profile_download_error_t;

typedef enum profile_download_trigger_result_data_choice_e {
    PROFILE_INSTALLATION_RESULT_CHOICE,
    PROFILE_DOWNLOAD_ERROR_CHOICE
} profile_download_trigger_result_data_choice_t;

typedef union profile_download_trigger_result_data_choice_value_u {
    pir_t profile_installation_result;
    profile_download_error_t profile_download_error;
} profile_download_trigger_result_data_choice_value_t;

typedef struct profile_download_trigger_result_data_s {
    profile_download_trigger_result_data_choice_t choice;        // Indicates the CHOICE of the profileDownloadTriggerResultData
    profile_download_trigger_result_data_choice_value_t value;   // Contain the value of the profileDownloadTriggerResultData CHOICE
} profile_download_trigger_result_data_t;

typedef struct profile_download_trigger_result_data_presence_s {
    bool eim_transaction_id;
} profile_download_trigger_result_data_presence_t;

typedef struct profile_download_trigger_result_s {
    transaction_id_t eim_transaction_id;
    profile_download_trigger_result_data_t profile_download_trigger_result_data; // Struct that represents profileDownloadTriggerResultData
    profile_download_trigger_result_data_presence_t field_is_present;
} profile_download_trigger_result_t;

// eimPackageError
typedef enum eim_package_error_from_ipa_to_eim_e {
    EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_INVALID_PACKAGE_FORMAT = 1,
    EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE = 2,
    EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR = 127
} eim_package_error_from_ipa_to_eim_t;

/* ProvideEimPackageResult */
typedef enum eim_package_result_choice_e {
    EUICC_PACKAGE_RESULT_CHOICE_PEPR,
    EPR_AND_NOTIFICATIONS_CHOICE_PEPR,
    IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR,
    PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR,
    EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR
} eim_package_result_choice_t;

typedef struct eim_package_result_response_error_data_presence_s {
    bool eim_transaction_id;
} eim_package_result_response_error_data_presence_t;

typedef struct eim_package_result_response_error_s {
    transaction_id_t eim_transaction_id;
    eim_package_error_from_ipa_to_eim_t eim_package_result_error_code;
    eim_package_result_response_error_data_presence_t field_is_present;
} eim_package_result_response_error_t;

typedef union eim_package_result_choice_value_u {
    euicc_package_result_esipa_t euicc_package_result;
    epr_and_notifications_t epr_and_notifications;
    ipa_euicc_data_response_t ipa_euicc_data_response;
    profile_download_trigger_result_t profile_download_trigger_result;
    eim_package_result_response_error_t eim_package_result_response_error;
} eim_package_result_choice_value_t;

typedef struct eim_package_result_s {
    eim_package_result_choice_t choice;
    eim_package_result_choice_value_t value;
} eim_package_result_t;

typedef struct provide_eim_package_result_data_presence_s {
    bool eid_value;
} provide_eim_package_result_data_presence_t;

typedef struct provide_eim_package_result_s {
    eid_t eid_value;
    eim_package_result_t eim_package_result;
    provide_eim_package_result_data_presence_t field_is_present;
} provide_eim_package_result_t;

/* HandleNotificationEsipa */
typedef struct pending_notification_s {
    uint8_t* pending_notification;
    uint32_t pending_notification_size;
} pending_notification_t;

typedef enum handle_notification_esipa_choice_e {
    PENDING_NOTIFICATION_CHOICE_HNE,
    PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE
} handle_notification_esipa_choice_t;

typedef union handle_notification_esipa_choice_value_u {
    pending_notification_t pending_notification;
    provide_eim_package_result_t provide_eim_package_result;
} handle_notification_esipa_choice_value_t;

typedef struct handle_notification_esipa_s {
    handle_notification_esipa_choice_t choice;
    handle_notification_esipa_choice_value_t value;
} handle_notification_esipa_t;

/* TransferEimPackageResponse */
typedef enum transfer_eim_package_response_choice_e {
    EUICC_PACKAGE_RESULT_CHOICE_TEPR,
    EPR_AND_NOTIFICATIONS_CHOICE_TEPR,
    IPA_EUICC_DATA_RESPONSE_CHOICE_TEPR,
    EIM_PACKAGE_RECEIVED_CHOICE_TEPR,
    EIM_PACKAGE_ERROR_CHOICE_TEPR
} transfer_eim_package_response_choice_t;

typedef union transfer_eim_package_response_choice_value_u {
    euicc_package_result_esipa_t euicc_package_result;
    epr_and_notifications_t epr_and_notifications;
    ipa_euicc_data_response_t ipa_euicc_data_response;
    eim_package_error_from_ipa_to_eim_t eim_package_error;
} transfer_eim_package_response_choice_value_t;

typedef struct transfer_eim_package_response_s {
    transfer_eim_package_response_choice_t choice;
    transfer_eim_package_response_choice_value_t value;
} transfer_eim_package_response_t;

/* GetEimPackageRequest */
typedef enum state_change_cause_e {
    STATE_CHANGE_CAUSE_OTHER_EIM = 0,
    STATE_CHANGE_CAUSE_FALLBACK = 1,
    STATE_CHANGE_CAUSE_EMERGENCY_PROFILE = 2,
    STATE_CHANGE_CAUSE_LOCAL = 3,
    STATE_CHANGE_CAUSE_RESET = 4,
    STATE_CHANGE_CAUSE_IMMEDIATE_ENABLE_PROFILE = 5,
    STATE_CHANGE_CAUSE_DEVICE_CHANGE = 6,
    STATE_CHANGE_CAUSE_UNDEFINED = 127
} state_change_cause_t;

typedef struct get_eim_package_request_data_presence_s {
    bool notify_state_change;
    bool rplmn;
} get_eim_package_request_data_presence_t;

typedef struct get_eim_package_request_s {
    eid_t eid;
    mcc_mnc_t rplmn;
    state_change_cause_t state_change_cause; // mandatory if NotifyStateChange is present
    get_eim_package_request_data_presence_t field_is_present;
} get_eim_package_request_t;

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
typedef struct initiate_authentication_request_esipa_data_presence_s {
    bool eim_transaction_id;
} initiate_authentication_request_esipa_data_presence_t;

/* InitiateAuthenticationRequestEsipa */
typedef struct initiate_authentication_request_esipa_s {
    challenge_t euicc_challenge;
#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
    fqdn_t smdp_address;
#endif
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    uint8_t* euicc_info_1;                                 // Pointer to a byte array that contain the euiccInfo1 TLV. Only if the field is present in the field_is_present structure.
    uint32_t euicc_info_1_size;
#endif
    transaction_id_t eim_transaction_id;                                    
    initiate_authentication_request_esipa_data_presence_t field_is_present;
} initiate_authentication_request_esipa_t;

/* AuthenticateClientRequestEsipa */
typedef struct authenticate_client_request_esipa_s {
  transaction_id_t transaction_id;
  uint8_t* authenticate_server_response;
  uint32_t authenticate_server_response_size;
} authenticate_client_request_esipa_t; 

/* CancelSessionRequestEsipa */
typedef struct cancel_session_request_esipa_s {
  transaction_id_t transaction_id;
  uint8_t* cancel_session_response;
  uint32_t cancel_session_response_size;
} cancel_session_request_esipa_t;

/* GetBoundProfilePackageRequestEsipa */
typedef struct get_bound_profile_package_request_esipa_s {
    transaction_id_t transaction_id;
    uint8_t* prepare_download_response;
    uint32_t prepare_download_response_size;
} get_bound_profile_package_request_esipa_t;
#endif

/* EsipaMessageFromIpaToEim */
typedef enum esipa_message_from_ipa_to_eim_choice_e {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE_EMFI,
    AUTHENTICATE_CLIENT_REQUEST_ESIPA_CHOICE_EMFI,
    GET_BOUND_PROFILE_PACKAGE_REQUEST_ESIPA_CHOICE_EMFI,
    CANCEL_SESSION_REQUEST_ESIPA_CHOICE_EMFI,
#endif
    HANDLE_NOTIFICATION_ESIPA_CHOICE_EMFI,
    TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE_EMFI,
    GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI,
    PROVIDE_EIM_PACKAGE_RESULT_CHOICE_EMFI
} esipa_message_from_ipa_to_eim_choice_t;

typedef union esipa_message_from_ipa_to_eim_choice_value_u {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    initiate_authentication_request_esipa_t initiate_authentication_request_esipa;
    authenticate_client_request_esipa_t authenticate_client_request_esipa;
    get_bound_profile_package_request_esipa_t get_bound_profile_package_request_esipa;
    cancel_session_request_esipa_t cancel_session_request_esipa;
#endif
    handle_notification_esipa_t handle_notification_esipa;
    transfer_eim_package_response_t transfer_eim_package_response;
    get_eim_package_request_t get_eim_package_request;
    provide_eim_package_result_t provide_eim_package_result;
} esipa_message_from_ipa_to_eim_choice_value_t;

typedef struct esipa_message_from_ipa_to_eim_s {
    esipa_message_from_ipa_to_eim_choice_t choice;
    esipa_message_from_ipa_to_eim_choice_value_t value;
} esipa_message_from_ipa_to_eim_t;
