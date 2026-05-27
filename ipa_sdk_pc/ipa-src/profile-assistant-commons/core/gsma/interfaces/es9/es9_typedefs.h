/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es10_typedefs.h"

/** InitiateAuthentication */
// InitiateAuthenticationRequest
typedef struct initiate_authentication_request_s {
    challenge_t euicc_challenge;
    fqdn_t smdp_address;
    uint8_t* euicc_info_1;
    uint32_t euicc_info_1_size;
} initiate_authentication_request_t;

// InitiateAuthenticationResponse
typedef enum initiate_authentication_response_choice_e {
    INITIATE_AUTHENTICATION_OK_CHOICE,
    INITIATE_AUTHENTICATION_ERROR_CHOICE,
} initiate_authentication_response_choice_t;

typedef struct initiate_authentication_ok_es9_s {
    transaction_id_t transaction_id;
    uint8_t* server_signed_1;
    uint32_t server_signed_1_size;
    uint8_t* server_signature_1;
    uint32_t server_signature_1_size;
    subject_key_identifier_t euicc_ci_pk_id_to_be_used;
    uint8_t* server_certificate;
    uint32_t server_certificate_size;
} initiate_authentication_ok_es9_t;

typedef enum initiate_authentication_error_e {
    INITIATE_AUTHENTICATION_ERROR_ES9_INVALID_DP_ADDRESS = 1,
    INITIATE_AUTHENTICATION_ERROR_ES9_EUICC_VERSION_NOT_SUPPORTED_BY_DP = 2,
    INITIATE_AUTHENTICATION_ERROR_ES9_CI_PK_ID_NOT_SUPPORTED = 3,
} initiate_authentication_error_t;

typedef union initiate_authentication_response_value_u {
    initiate_authentication_ok_es9_t ok;
    initiate_authentication_error_t error;
} initiate_authentication_response_value_t;

typedef struct initiate_authentication_response_s {
    void* context;
    initiate_authentication_response_choice_t choice;
    initiate_authentication_response_value_t value;
} initiate_authentication_response_t;

/** AuthenticateClient */
// AuthenticateClientRequest
typedef struct authenticate_client_request_s {
    transaction_id_t transaction_id;
    uint8_t* authenticate_server_response;
    uint32_t authenticate_server_response_size;
} authenticate_client_request_t;

// AuthenticateClientResponseEs9
typedef enum authenticate_client_response_es9_choice_u {
    AUTHENTICATE_CLIENT_OK_CHOICE,
    AUTHENTICATE_CLIENT_ERROR_CHOICE
} authenticate_client_response_es9_choice_t;

typedef struct authenticate_client_ok_s {
    transaction_id_t transaction_id;
    uint8_t* profile_metadata;   /* Main TAG included */
    uint32_t profile_metadata_size;
    uint8_t* smdp_signed_2;      /* Main TAG included */
    uint32_t smdp_signed_2_size;
    uint8_t* smdp_signature_2;   /* Main TAG included */
    uint32_t smdp_signature_2_size;
    uint8_t* smdp_certificate;   /* Main TAG included */
    uint32_t smdp_certificate_size;
} authenticate_client_ok_t;

typedef enum authenticate_client_error_e {
    AUTHENTICATE_CLIENT_ERROR_ES9_EUM_CERTIFICATE_INVALID = 1,
    AUTHENTICATE_CLIENT_ERROR_ES9_EUM_CERTIFICATE_EXPIRED = 2,
    AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_CERTIFICATE_INVALID = 3,
    AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_CERTIFICATE_EXPIRED = 4,
    AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_SIGNATURE_INVALID = 5,
    AUTHENTICATE_CLIENT_ERROR_ES9_MATCHING_ID_REFUSED = 6,
    AUTHENTICATE_CLIENT_ERROR_ES9_EID_MISMATCH = 7,
    AUTHENTICATE_CLIENT_ERROR_ES9_NO_ELIGIBLE_PROFILE = 8,
    AUTHENTICATE_CLIENT_ERROR_ES9_CI_PK_UNKNOWN = 9,
    AUTHENTICATE_CLIENT_ERROR_ES9_INVALID_TRANSACTION_ID = 10,
    AUTHENTICATE_CLIENT_ERROR_ES9_INSUFFICIENT_MEMORY = 11,
    AUTHENTICATE_CLIENT_ERROR_ES9_UNDEFINED_ERROR = 127
} authenticate_client_error_t;

typedef union authenticate_client_response_es9_value_u {
    authenticate_client_ok_t ok;
    authenticate_client_error_t error;
} authenticate_client_response_es9_value_t;

typedef struct authenticate_client_response_es9_s {
    void* context;
    authenticate_client_response_es9_choice_t choice;
    authenticate_client_response_es9_value_t value;
} authenticate_client_response_es9_t;

/** GetBoundProfilePackage */
// GetBoundProfilePackageRequest
typedef struct get_bound_profile_package_request_s {
    transaction_id_t transaction_id;
    uint8_t* prepare_download_response;
    uint32_t prepare_download_response_size;
} get_bound_profile_package_request_t;

// GetBoundProfilePackageResponse
typedef enum get_bound_profile_package_error_e {
    GET_BPP_ERROR_ES9_EUICC_SIGNATURE_INVALID = 1,
    GET_BPP_ERROR_ES9_CONFIRMATION_CODE_MISSING = 2,
    GET_BPP_ERROR_ES9_CONFIRMATION_CODE_REFUSED = 3,
    GET_BPP_ERROR_ES9_CONFIRMATION_CODE_RETRIES_EXCEEDED = 4,
    GET_BPP_ERROR_ES9_BPP_REBINDING_REFUSED = 5,
    GET_BPP_ERROR_ES9_DOWNLOAD_ORDER_EXPIRED = 6,
    GET_BPP_ERROR_ES9_INVALID_TRANSACTION_ID = 95,
    GET_BPP_ERROR_ES9_UNDEFINED_ERROR = 127
} get_bound_profile_package_error_t;

typedef struct get_bound_profile_package_ok_s {
    transaction_id_t transaction_id;
    uint8_t* bound_profile_package;
    uint32_t bound_profile_package_size;
} get_bound_profile_package_ok_t;

typedef enum get_bound_profile_package_response_choice_e {
    GET_BOUND_PROFILE_PACKAGE_OK,
    GET_BOUND_PROFILE_PACKAGE_ERROR
} get_bound_profile_package_response_choice_t;

typedef union get_bound_profile_package_response_value_u {
    get_bound_profile_package_ok_t ok;
    get_bound_profile_package_error_t error;
} get_bound_profile_package_response_value_t;

typedef struct get_bound_profile_package_response_s {
    void* context;
    get_bound_profile_package_response_choice_t choice;
    get_bound_profile_package_response_value_t value;
} get_bound_profile_package_response_t;

/** CancelSession */
typedef struct cancel_session_request_es9_s {
    transaction_id_t transaction_id;
    uint8_t* cancel_session_response;
    uint32_t cancel_session_response_size;
} cancel_session_request_es9_t;

typedef enum cancel_session_response_es9_choice_e {
    CANCEL_SESSION_OK,
    CANCEL_SESSION_ERROR
} cancel_session_response_es9_choice_t;

typedef enum cancel_session_error_e {
    CANCEL_SESSION_ERROR_ES9_INVALID_TRANSACTION_ID = 1,
    CANCEL_SESSION_ERROR_ES9_EUICC_SIGNATURE_INVALID = 2,
    CANCEL_SESSION_ERROR_ES9_UNDEFINED_ERROR = 127
} cancel_session_error_t;

typedef struct cancel_session_response_es9_s {
    cancel_session_response_es9_choice_t choice;
    cancel_session_error_t error; // Only if choice is CANCEL_SESSION_ERROR
} cancel_session_response_es9_t;
