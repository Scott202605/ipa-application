/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es10_typedefs.h"
#include "rsp.h"

/* eIM Package Request */

// EuiccPackageRequest 
typedef enum euicc_package_choice_e {
    EUICC_PACKAGE_CHOICE_PSMO_LIST,
    EUICC_PACKAGE_CHOICE_ECO_LIST
} euicc_package_choice_t;

typedef union euicc_package_choice_value_u {
    asn1_list_iterator_t psmo_list;
    asn1_list_iterator_t eco_list;
} euicc_package_choice_value_t;

typedef struct euicc_package_s {
    euicc_package_choice_t choice;
    euicc_package_choice_value_t value;
} euicc_package_t;

typedef struct euicc_package_signed_data_presence_s {
    bool eim_transaction_id;
} euicc_package_signed_data_presence_t;

typedef struct euicc_package_signed_s {
    uint8_t* eim_id;
    uint8_t eim_id_size;
    eid_t eid;
    uint32_t counter_value;
    transaction_id_t eim_transaction_id;
    euicc_package_t euicc_package;
    euicc_package_signed_data_presence_t field_is_present;
} euicc_package_signed_t;

typedef struct euicc_package_request_s {
    euicc_package_signed_t euicc_package_signed;
    uint8_t* eim_signature;
    uint32_t eim_signature_size;
} euicc_package_request_t;

typedef struct euicc_package_request_plain_s {
    uint8_t* euicc_package_request;
    uint32_t euicc_package_request_size;
} euicc_package_request_plain_t;

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
typedef struct truncated_subject_key_identifier_s {
	uint8_t value[SUBJECT_KEY_IDENTIFIER_SIZE];
	uint8_t size;
} truncated_subject_key_identifier_t;
#endif

typedef union subject_key_identifier_possibly_truncated_u {
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    truncated_subject_key_identifier_t subject_key_identifier;
#else
    subject_key_identifier_t subject_key_identifier;
#endif
} subject_key_identifier_possibly_truncated_t;

// IpaEuiccDataRequest
typedef struct ipa_euicc_data_request_tag_list_s {
    bool notifications_list;    // True if the List of Notifications tag is present in the tag list, otherwise false.
    bool default_smdp;          // True if the Default SM-DP+ address tag is present in the tag list, otherwise false.
    bool euicc_package_results; // True if the eUICC Package Results tag is present in the tag list, otherwise false.
    bool euicc_info_1;          // True if the eUICCInfo1 tag is present in the tag list, otherwise false.
    bool euicc_info_2;          // True if the eUICCInfo2 tag is present in the tag list, otherwise false.
    bool root_smds;             // True if the Root SM-DS address tag is present in the tag list, otherwise false.
    bool association_token;     // True if the Association token tag is present in the tag list, otherwise false.
    bool eum_cert;              // True if the EUM certificate tag is present in the tag list, otherwise false.
    bool euicc_cert;            // True if the eUICC certificate tag is present in the tag list, otherwise false.
    bool ipa_capabilities;      // True if the IPA Capabilities tag is present in the tag list, otherwise false.
    bool device_information;    // True if the Device Information tag is present in the tag list, otherwise false.
} ipa_euicc_data_request_tag_list_t;

typedef struct ipa_euicc_data_request_data_presence_s {
    bool euicc_ci_pk_id;                        // True if the euiccCiPKId field is present in the IpaEuiccDataRequest TLV, otherwise false.
    bool search_criteria_notification;          // True if the searchCriteriaNotification field is present in the IpaEuiccDataRequest TLV, otherwise false.
    bool search_criteria_euicc_package_result;  // True if the searchCriteriaEuiccPackageResult field is present in the IpaEuiccDataRequest TLV, otherwise false.
    bool eim_transaction_id;                    // True if the eimTransactionId field is present in the IpaEuiccDataRequest TLV, otherwise false.
} ipa_euicc_data_request_data_presence_t;

typedef enum search_criteria_notification_choice_e {
    ESIPA_NOTIFICATION_SEQ_NUMBER_CHOICE,
    ESIPA_NOTIFICATION_PROFILE_MANAGEMENT_OPERATION_CHOICE
} search_criteria_notification_choice_t;

typedef struct search_criteria_notification_s {
    retrieve_notifications_list_request_search_criteria_choice_value_t value;
    search_criteria_notification_choice_t choice;
} search_criteria_notification_t;

typedef enum search_criteria_euicc_package_result_choice_e {
    ESIPA_EUICC_PACKAGE_RESULT_SEQ_NUMBER_CHOICE
} search_criteria_euicc_package_result_choice_t;

typedef union search_criteria_euicc_package_result_value_u {
    uint32_t seq_number;
} search_criteria_euicc_package_result_value_t;

typedef struct search_criteria_euicc_package_result_s {
    search_criteria_euicc_package_result_value_t value;
    search_criteria_euicc_package_result_choice_t choice;
} search_criteria_euicc_package_result_t;

typedef struct ipa_euicc_data_request_s {
    ipa_euicc_data_request_tag_list_t tag_list;
    subject_key_identifier_possibly_truncated_t euicc_ci_pk_id_to_be_used;
    search_criteria_notification_t search_criteria_notification;
    search_criteria_euicc_package_result_t search_criteria_euicc_package_result;
    transaction_id_t eim_transaction_id;
    ipa_euicc_data_request_data_presence_t field_is_present;
} ipa_euicc_data_request_t;

// ProfileDownloadTriggerRequest
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
typedef enum profile_download_data_choice_e {
    ACTIVATION_CODE_CHOICE,
    CONTACT_DEFAULT_SMDP_CHOICE,
    CONTACT_SMDS_CHOICE
} profile_download_data_choice_t;

typedef struct profile_download_data_s {
    const unsigned char* data; // Can point either to activationCode or smdsAdress, depending on the choice value
    uint32_t data_len;
    profile_download_data_choice_t choice;
} profile_download_data_t;
#endif

typedef struct profile_download_trigger_request_data_presence_s {
    bool eim_transaction_id;
} profile_download_trigger_request_data_presence_t;

typedef struct profile_download_trigger_request_s {
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
    profile_download_data_t profile_download_data;  // Struct that represents ProfileDownloadData
#endif
    transaction_id_t eim_transaction_id;
    profile_download_trigger_request_data_presence_t field_is_present;
} profile_download_trigger_request_t;

// eimPackageError
typedef enum eim_package_error_from_eim_to_ipa_e {
    EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE = 1,
    EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_EID_NOT_FOUND = 2,
    EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_INVALID_EID = 3,
    EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_MISSING_EID = 4,
    EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_UNDEFINED_ERROR = 127
} eim_package_error_from_eim_to_ipa_t;

// EimAcknowledgements
typedef struct eim_acknowledgements_s {
    asn1_list_iterator_t sequence_number_list;
} eim_acknowledgements_t;

/* TransferEimPackageRequest */
typedef enum transfer_eim_package_request_choice_e {
    EUICC_PACKAGE_REQUEST_CHOICE_TEPR,
    IPA_EUICC_DATA_REQUEST_CHOICE_TEPR,
    EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR,
    PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR
} transfer_eim_package_request_choice_t;

typedef union transfer_eim_package_request_choice_value_u {
    euicc_package_request_plain_t euicc_package_request;
    ipa_euicc_data_request_t ipa_euicc_data_request;
    eim_acknowledgements_t eim_acknowledgements;
    profile_download_trigger_request_t profile_download_trigger_request;
} transfer_eim_package_request_choice_value_t;

typedef struct transfer_eim_package_request_s {
    transfer_eim_package_request_choice_t choice;
    transfer_eim_package_request_choice_value_t value;
} transfer_eim_package_request_t;

/* GetEimPackageResponse */
typedef enum get_eim_package_response_choice_e {
    EUICC_PACKAGE_REQUEST_CHOICE_GEPR,
    IPA_EUICC_DATA_REQUEST_CHOICE_GEPR,
    PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR,
    EIM_PACKAGE_ERROR_CHOICE_GEPR
} get_eim_package_response_choice_t;

typedef union get_eim_package_response_choice_value_u {
    euicc_package_request_plain_t euicc_package_request;
    ipa_euicc_data_request_t ipa_euicc_data_request;
    profile_download_trigger_request_t profile_download_trigger_request;
    eim_package_error_from_eim_to_ipa_t eim_package_error;
} get_eim_package_response_choice_value_t;

typedef struct get_eim_package_response_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context;
#endif
    get_eim_package_response_choice_t choice;
    get_eim_package_response_choice_value_t value;
} get_eim_package_response_t;

/* ProvideEimPackageResultResponse */
typedef enum provide_eim_package_result_error_e {
    PROVIDE_EIM_PKG_RESULT_ERROR_EID_NOT_FOUND = 2,
    PROVIDE_EIM_PKG_RESULT_ERROR_INVALID_EID = 3,
    PROVIDE_EIM_PKG_RESULT_ERROR_MISSING_EID = 4,
    PROVIDE_EIM_PKG_RESULT_ERROR_UNDEFINED_ERROR = 127
} provide_eim_package_result_error_t;

typedef enum provide_eim_package_result_response_choice_e {
    EIM_ACKNOWLEDGEMENTS_CHOICE_PEPRR,
    EMPTY_RESPONSE_CHOICE_PEPRR,
    PROVIDE_EIM_PACKAGE_RESULT_ERROR_CHOICE_PEPRR,
} provide_eim_package_result_response_choice_t;

typedef union provide_eim_package_result_response_choice_value_u {
    eim_acknowledgements_t eim_acknowledgements;
    provide_eim_package_result_error_t provide_eim_package_result_error;
} provide_eim_package_result_response_choice_value_t;

typedef struct provide_eim_package_result_response_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context;
#endif
    provide_eim_package_result_response_choice_t choice;
    provide_eim_package_result_response_choice_value_t value;
} provide_eim_package_result_response_t;

/* InitiateAuthenticationResponseEsipa */
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) || !defined(IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION)
typedef struct initiate_authentication_response_esipa_data_presence_s {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    bool transaction_id;
#endif
#ifndef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
    bool matching_id;
#endif
} initiate_authentication_response_esipa_data_presence_t;
#endif

typedef struct initiate_authentication_ok_esipa_s {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    transaction_id_t transaction_id;
#endif
    subject_key_identifier_possibly_truncated_t euicc_ci_pk_id_to_be_used;
    uint8_t* server_signed_1; /* Main TAG included */
    uint32_t server_signed_1_size;
    uint8_t* server_signature_1; /* Main TAG included */
    uint8_t server_signature_1_size;
    uint8_t* server_certificate; /* Main TAG included */
    uint32_t server_certificate_size;
#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
    uint8_t* ctx_params_1_value;
    uint16_t ctx_params_1_value_size;
#else 
    uint8_t* matching_id; 
    uint8_t matching_id_size;
#endif
#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) || !defined(IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION)
    initiate_authentication_response_esipa_data_presence_t field_is_present;
#endif
}initiate_authentication_ok_esipa_t;

typedef enum initiate_authentication_error_esipa_e {
    INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_DP_ADDRESS = 1,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_EUICC_VERSION_NOT_SUPPORTED_BY_DP = 2,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED = 3,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_ADDRESS_MISMATCH = 50,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_OID_MISMATCH = 51,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_EIM_TRANSACTION_ID = 52,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_UNDEFINED_ERROR = 127
} initiate_authentication_error_esipa_t;

typedef enum initiate_authentication_response_esipa_choice_e {
    INITIATE_AUTHENTICATION_OK_ESIPA_CHOICE,
    INITIATE_AUTHENTICATION_ERROR_ESIPA_CHOICE
} initiate_authentication_response_esipa_choice_t;

typedef union initiate_authentication_response_esipa_value_u {
    initiate_authentication_ok_esipa_t initiate_authentication_ok_esipa;
    initiate_authentication_error_esipa_t initiate_authentication_error_esipa;
} initiate_authentication_response_esipa_value_t;

typedef struct initiate_authentication_response_esipa_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context; /* Buffer context for deferred memory management */
#endif
    initiate_authentication_response_esipa_choice_t choice;
    initiate_authentication_response_esipa_value_t value;
} initiate_authentication_response_esipa_t;

/* AuthenticateClientResponseEsipa */
typedef struct authenticate_client_ok_dp_esipa_data_presence_s {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    bool transaction_id;
#endif
    bool hash_cc;
} authenticate_client_ok_dp_esipa_data_presence_t;

typedef struct authenticate_client_ok_dp_esipa_s {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    transaction_id_t transaction_id;
#endif
#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
    uint8_t* profile_metadata;   /* Main TAG included */
    uint32_t profile_metadata_size;
#endif
    uint8_t* smdp_signed_2; /* Main TAG included */
    uint32_t smdp_signed_2_size;
    uint8_t* smdp_signature_2; /* Main TAG included */
    uint8_t smdp_signature_2_size;
    uint8_t* smdp_certificate; /* Main TAG included */
    uint32_t smdp_certificate_size;
    sha256_hash_t hash_cc;
    authenticate_client_ok_dp_esipa_data_presence_t field_is_present;
} authenticate_client_ok_dp_esipa_t;

typedef struct authenticate_client_ok_ds_esipa_data_presence_s {
    bool profile_download_trigger;
} authenticate_client_ok_ds_esipa_data_presence_t;

typedef struct authenticate_client_ok_ds_esipa_s {
    transaction_id_t transaction_id;
    profile_download_trigger_request_t profile_download_trigger;
    authenticate_client_ok_ds_esipa_data_presence_t field_is_present;
} authenticate_client_ok_ds_esipa_t;

typedef enum authenticate_client_error_esipa_e {
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_INVALID = 1,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_EXPIRED = 2,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_INVALID = 3,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_EXPIRED = 4,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_SIGNATURE_INVALID = 5,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_MATCHING_ID_REFUSED = 6,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EID_MISMATCH = 7,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_NO_ELIGIBLE_PROFILE = 8,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_CI_PK_UNKNOWN = 9,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_INVALID_TRANSACTION_ID = 10,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_INSUFFICIENT_MEMORY = 11,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_PPR_NOT_ALLOWED = 50,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_EVENT_ID_UNKNOWN = 56,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_UNDEFINED_ERROR = 127,
} authenticate_client_error_esipa_t;

typedef enum authenticate_client_response_esipa_choice_e {
    AUTHENTICATE_CLIENT_OK_DP_ESIPA_CHOICE,
    AUTHENTICATE_CLIENT_OK_DS_ESIPA_CHOICE,
    AUTHENTICATE_CLIENT_ERROR_ESIPA_CHOICE
} authenticate_client_response_esipa_choice_t;

typedef union authenticate_client_response_esipa_value_u {
    authenticate_client_ok_dp_esipa_t authenticate_client_ok_dp_esipa;
    authenticate_client_ok_ds_esipa_t authenticate_client_ok_ds_esipa;
    authenticate_client_error_esipa_t authenticate_client_error_esipa;
} authenticate_client_response_esipa_value_t;

typedef struct authenticate_client_response_esipa_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context; /* Buffer context for deferred memory management */
#endif
    authenticate_client_response_esipa_choice_t choice;
    authenticate_client_response_esipa_value_t value;
} authenticate_client_response_esipa_t;

/* GetBoundProfilePackageResponseEsipa */
typedef struct get_bound_profile_package_ok_esipa_s {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    transaction_id_t transaction_id;
#endif
    uint8_t* bound_profile_package;
    uint32_t bound_profile_package_size;
} get_bound_profile_package_ok_esipa_t;

typedef enum get_bound_profile_package_error_esipa_e {
    GET_BPP_ERROR_ESIPA_EUICC_SIGNATURE_INVALID = 1,
    GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_MISSING = 2,
    GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_REFUSED = 3,
    GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_RETRIES_EXCEEDED = 4,
    GET_BPP_ERROR_ESIPA_BPP_REBINDING_REFUSED = 5,
    GET_BPP_ERROR_ESIPA_DOWNLOAD_ORDER_EXPIRED = 6,
    GET_BPP_ERROR_ESIPA_METADATA_MISMATCH = 50,
    GET_BPP_ERROR_ESIPA_INVALID_TRANSACTION_ID = 95,
    GET_BPP_ERROR_ESIPA_UNDEFINED_ERROR = 127,
} get_bound_profile_package_error_esipa_t;

typedef enum get_bound_profile_package_response_esipa_choice_e {
    GET_BOUND_PROFILE_PACKAGE_OK_ESIPA_CHOICE,
    GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA_CHOICE
} get_bound_profile_package_response_esipa_choice_t;

typedef union get_bound_profile_package_response_esipa_value_u {
    get_bound_profile_package_ok_esipa_t get_bound_profile_package_ok_esipa;
    get_bound_profile_package_error_esipa_t get_bound_profile_package_error_esipa;
} get_bound_profile_package_response_esipa_value_t;

typedef struct get_bound_profile_package_response_esipa_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context; /* Buffer context for deferred memory management */
#endif
    get_bound_profile_package_response_esipa_choice_t choice;
    get_bound_profile_package_response_esipa_value_t value;
} get_bound_profile_package_response_esipa_t;

/* CancelSessionResponseEsipa */
typedef enum cancel_session_response_esipa_choice_e {
    CANCEL_SESSION_OK_ESIPA,
    CANCEL_SESSION_ERROR_ESIPA
} cancel_session_response_esipa_choice_t;

typedef enum cancel_session_error_esipa_e {
    CANCEL_SESSION_ERROR_ESIPA_INVALID_TRANSACTION_ID = 1,
    CANCEL_SESSION_ERROR_ESIPA_EUICC_SIGNATURE_INVALID = 2,
    CANCEL_SESSION_ERROR_ESIPA_UNDEFINED_ERROR = 127
} cancel_session_error_esipa_t;

typedef struct cancel_session_response_esipa_s {
#ifdef ENABLE_HTTP_ESIPA
    void* context; /* Buffer context for deferred memory management */
#endif
    cancel_session_response_esipa_choice_t choice;
    cancel_session_error_esipa_t cancel_session_error; // Only if choice is CANCEL_SESSION_ERROR
} cancel_session_response_esipa_t; 
#endif

/* EsipaMessageFromEimToIpa */
typedef enum esipa_message_from_eim_to_ipa_choice_e {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    INITIATE_AUTHENTICATION_RESPONSE_ESIPA_CHOICE,
    AUTHENTICATE_CLIENT_RESPONSE_ESIPA_CHOICE,
    GET_BOUND_PROFILE_PACKAGE_RESPONSE_ESIPA_CHOICE,
    CANCEL_SESSION_RESPONSE_ESIPA_CHOICE,
#endif
    TRANSFER_EIM_PACKAGE_REQUEST_CHOICE,
    GET_EIM_PACKAGE_RESPONSE_CHOICE,
    PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE
} esipa_message_from_eim_to_ipa_choice_t;

typedef union esipa_message_from_eim_to_ipa_choice_value_u {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    initiate_authentication_response_esipa_t initiate_authentication_response_esipa;
    authenticate_client_response_esipa_t authenticate_client_response_esipa;
    get_bound_profile_package_response_esipa_t get_bound_profile_package_response_esipa;
    cancel_session_response_esipa_t cancel_session_response_esipa;
#endif
    transfer_eim_package_request_t transfer_eim_package_request;
    get_eim_package_response_t get_eim_package_response;
    provide_eim_package_result_response_t provide_eim_package_result_response;
} esipa_message_from_eim_to_ipa_choice_value_t;

typedef struct esipa_message_from_eim_to_ipa_s {
    esipa_message_from_eim_to_ipa_choice_t choice;
    esipa_message_from_eim_to_ipa_choice_value_t value;
} esipa_message_from_eim_to_ipa_t;
