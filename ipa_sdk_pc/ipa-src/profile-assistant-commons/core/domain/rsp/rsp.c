/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <ctype.h>

#include "rsp.h"
#include "mutual_authentication.h"
#include "notifications_delivery.h"
#include "sha256.h"
#include "es10_tlv_extractor.h"
#include "es10_display.h"
#include "log.h"
#include "memory_manager.h"
#include "ppr_verification.h"
#ifdef SUPPORT_USER_CONSENT_INTERFACE
#include "user_consent.h"
#endif

#define ACTIVATION_CODE_PREFIX				"LPA:"
#define ACTIVATION_CODE_PREFIX_LEN          4
#define ACTIVATION_CODE_DELIMITER  			'$'
#define ACTIVATION_CODE_FORMAT  			'1'
#define ACTIVATION_CODE_CC_REQUIRED_FLAG	'1'

#ifdef SUPPORT_USER_CONSENT_INTERFACE
#define INITIAL_USER_CONSENT_STR "There is already an enabled Profile with PPR1 (Disabling of this Profile is not allowed).\nAre you sure you want to start downloading a new profile?"
#define PPR1_AND_PPR2_USER_CONSENT_STR "The profile that you are about to install can be disabled and deleted only under the terms you have agreed with your service provider. Approve installation?"
#define PPR1_USER_CONSENT_STR "The profile that you are about to install can be disabled only under the terms you have agreed with your service provider. Approve installation?"
#define PPR2_USER_CONSENT_STR "The profile that you are about to install can be deleted only under the terms you have agreed with your service provider. Approve installation?"
#define NO_PPR_USER_CONSENT_STR "Approve installation?"
#define USER_CONSENT_TIMEOUT_VALUE 30 //seconds
#endif

#define STR_CANCEL_SESSION_ERROR(E) \
((E) == CANCEL_SESSION_ERROR_ES9_INVALID_TRANSACTION_ID ? "invalidTransactionId" : \
((E) == CANCEL_SESSION_ERROR_ES9_EUICC_SIGNATURE_INVALID ? "euiccSignatureInvalid" : \
((E) == CANCEL_SESSION_ERROR_ES9_UNDEFINED_ERROR ? "undefinedError" : \
"Unknown")))

#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
#define STR_IMMEDIATE_ENABLE_RESULT_ERROR(E) \
((E) == IMMEDIATE_ENABLE_RESULT_IMMEDIATE_ENABLE_NOT_AVAILABLE ? "immediateEnableNotAvailable" : \
((E) == IMMEDIATE_ENABLE_RESULT_NO_SESSION_CONTEXT ? "noSessionContext" : \
((E) == IMMEDIATE_ENABLE_RESULT_CAT_BUSY ? "catBusy" : \
((E) == IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR ? "undefinedError" : \
"Unknown"))))
#endif

typedef enum rsp_result_choice_s {
    RSP_RESULT_CHOICE_OK,
    RSP_RESULT_CHOICE_CANCEL_SESSION
} rsp_result_choice_t;

// Result for general purposes
typedef struct rsp_result_s {
    rsp_result_choice_t choice;
    cancel_session_reason_t cancel_session_reason; // Only in case choice is RSP_RESULT_CHOICE_CANCEL_SESSION
} rsp_result_t;

// Result for rsp__profile_installation
typedef union rsp_profile_installation_result_value_u {
    pir_t pir;
    cancel_session_reason_t cancel_session_reason;
} rsp_profile_installation_result_value_t;

typedef struct rsp_profile_installation_result_s {
    rsp_result_choice_t choice;
    rsp_profile_installation_result_value_t value;
} rsp_profile_installation_result_t;

// Result for rsp__prepare_download
typedef union rsp_prepare_download_result_value_u {
    get_bound_profile_package_request_t get_bound_profile_package_request;
    cancel_session_reason_t cancel_session_reason;
} rsp_prepare_download_result_value_t;

typedef struct rsp_prepare_download_result_s {
    rsp_result_choice_t choice;
    rsp_prepare_download_result_value_t value;
} rsp_prepare_download_result_t;

static ErrCode rsp__profile_download_and_installation(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, bool is_default_dp, const uint8_t* matching_id, const uint8_t matching_id_len, const bool ccrf, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir);
static ErrCode rsp__download_rejection(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, const transaction_id_t* transaction_id, const cancel_session_reason_t reason);
static ErrCode rsp__download_confirmation(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, bool is_default_dp, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, authenticate_client_response_es9_t* authenticate_client_response, pir_t* pir);
static ErrCode rsp__profile_installation(es9_t* const es9, es10_t* const es10, bool is_default_dp, get_bound_profile_package_response_t* get_bpp_response, rsp_profile_installation_result_t* result);
static ErrCode rsp__prepare_download(es9_t* const es9, es10_t* const es10, const char* smdp_address, authenticate_client_response_es9_t* authenticate_client_response, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, rsp_prepare_download_result_t* result);
static ErrCode rsp__load_bound_profile_package(es10_t* const es10, const uint8_t* bpp, uint32_t bpp_size, uint8_t** pir, uint32_t* pir_size);
static ErrCode rsp__initial_user_consent(es10_t* const es10);
static ErrCode rsp__profile_can_be_downloaded(es10_t* const es10, const uint8_t* profile_metadata, uint32_t profile_metadata_size, rsp_result_t* result);
static ErrCode rsp__check_profile_pprs_are_allowed(es10_t* const es10, const profile_info_t* profile_info, ppr_verification_result_t* ppr_verification_result);
static ErrCode rsp__verify_profile_metadata(es10_t* const es10, const uint8_t* profile_metadata, uint32_t profile_metadata_size, rsp_result_t* result);
static ErrCode rsp__calculate_hash_confirmation_code(const smdp_signed_2_t* smdp_signed_2, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, sha256_hash_t* hash_cc);
static ErrCode rsp__retrieve_euicc_default_dp_address(es10_t* const es10, fqdn_t* default_dp_address);
static ErrCode rsp__retrieve_euicc_root_ds_address(es10_t* const es10, fqdn_t* root_ds_address);
static ErrCode rsp__retrieve_euicc_configured_addresses(es10_t* const es10, euicc_configured_addresses_response_t* euicc_addresses);
static ErrCode rsp__retrieve_enabled_profile(es10_t* const es10, bool* is_profile_enabled, profile_info_t* obj);
static void rsp__fqdn_to_lowercase(fqdn_t* fqdn);
static void rsp__free_get_bound_profile_package_request(get_bound_profile_package_request_t* get_bound_profile_package_request);

ErrCode rsp__activation_code(es9_t* const es9, es10_t* const es10, const uint8_t* activation_code, const uint32_t activation_code_len, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir) {
    ErrCode rc;
    activation_code_t ac;
    fqdn_t smdp_address;

    if ((rc = rsp__parse_activation_code(activation_code, activation_code_len, &ac)) != eOk) {
        LOGE("[rsp__activation_code] The Activation Code has an invalid format, rc %d", rc);
        return rc;
    }

    if ((rc = rsp__utf8_to_fqdn(ac.smdp_address, ac.smdp_address_size, &smdp_address)) != eOk) {
        LOGE("[rsp__activation_code] Error parsing the SMDP+ Address from the Activation Code to a FQDN, rc %d", rc);
        return rc;
    }

    return rsp__smdp(es9, es10, &smdp_address, ac.ac_token, ac.ac_token_size, ac.ccrf, confirmation_code, confirmation_code_len, pir);
}

ErrCode rsp__smdp(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, const uint8_t* matching_id, const uint8_t matching_id_len, const bool ccrf, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir) {
    return rsp__profile_download_and_installation(es9, es10, smdp_address, false, matching_id, matching_id_len, ccrf, confirmation_code, confirmation_code_len, pir);
}

ErrCode rsp__default_smdp(es9_t* const es9, es10_t* const es10, pir_t* pir) {
    ErrCode rc;
    fqdn_t default_dp_address;

    /* Retrieve the default SM-DP+ Address */
    if ((rc = rsp__retrieve_euicc_default_dp_address(es10, &default_dp_address)) != eOk) {
        LOGE("[rsp__default_smdp] Error on retrieve the defaultDpAddress from the UICC, rc %d", rc);
        return rc;
    }

    /* Start the RSP procedure against the default SMDP+ */
    return rsp__profile_download_and_installation(es9, es10, &default_dp_address, true, NULL, 0, false, NULL, 0, pir);
}

ErrCode rsp__smds(es9_t* const es9, es10_t* const es10, es11_t* const es11, fqdn_t* smds_address, pir_t** pir_list, uint32_t* pir_list_size) {
    ErrCode rc;
    authenticate_client_response_es11_t authenticate_client_response;
    event_entry_t event;
    uint32_t event_entry_list_size;
    *pir_list = NULL; // In case there is no event
    *pir_list_size = 0;

    /* Log input parameters */
    rsp__fqdn_to_lowercase(smds_address);
    LOGD("[rsp__smdp] RSP SM-DS address: %s", smds_address->fqdn);

    if ((rc = mutual_authentication__smds(es10, es11, smds_address, &authenticate_client_response)) != eOk) {
        LOGE("[rsp__smds] Error on Mutual Authentication against the SMDS (%s), rc %d", smds_address, rc);
        return rc;
    }

    /* Check if the AuthenticateClientResponseEs11 is an error response */
    if (AUTHENTICATE_CLIENT_RESPONSE_ES11_ERROR == authenticate_client_response.choice) {
        LOGE("[rsp__smds] The AuthenticateClientResponseEs11 has an authenticateClientError(%d). Aborting the SMDS RSP", authenticate_client_response.choice);
        es11__free_authenticate_client_response(&authenticate_client_response);
        return eFatal;
    }

    /* Check if there is any event entry */
    if ((rc = es11__get_event_entry_list_size(es11, &authenticate_client_response, &event_entry_list_size)) != eOk) {
        LOGE("[rsp__smds] Error extracting the size of the eventEntries list, rc %d", rc);
        es11__free_authenticate_client_response(&authenticate_client_response);
        return eFatal;
    }

    if (0 == event_entry_list_size) {
        LOGI("The SM-DS '%s' does not have any events recorded", smds_address->fqdn);
        es11__free_authenticate_client_response(&authenticate_client_response);
        return eOk;
    } else {
        LOGI("%u events found in the SM-DS '%s'", event_entry_list_size, smds_address->fqdn);
        *pir_list = M_calloc(event_entry_list_size, sizeof(pir_t));
        if (!(*pir_list)) {
            LOGE("[rsp__smds] Error allocating data for the PIR List");
            es11__free_authenticate_client_response(&authenticate_client_response);
            return eNoMem;
        }
    }


    /* Process each event */
    while ((rc = es11__get_next_event_entry(es11, &authenticate_client_response, &event)) == eOk) {
        LOG_UTF8_DATA(eLogInfo, "SM-DS Event RSP Server address: ", event.rsp_server_address, event.rsp_server_address_len);
        LOG_UTF8_DATA(eLogInfo, "SM-DS Event ID: ", event.event_id, event.event_id_len);
        // Parse the UTF8 event address to FQDN object (we reuse the FQDN parameter to save space)
        if ((rc = rsp__utf8_to_fqdn(event.rsp_server_address, event.rsp_server_address_len, smds_address)) == eOk) {
            // Start the RSP process against the SMDP+
            if ((rc = rsp__smdp(es9, es10, smds_address, event.event_id, event.event_id_len, false, NULL, 0, &(*pir_list)[*pir_list_size])) == eOk) {
                LOGI("SM-DS event processed sucessfully");
                (*pir_list_size)++;
            } else {
                LOGE("[rsp__smds] Error processing the SM-DS event, rc %d", rc);
            }
        } else {
            LOGE("[rsp__smds] Invalid Event Address, rc %d", rc);
        }
    }

    es11__free_authenticate_client_response(&authenticate_client_response);
    if (event_entry_list_size == *pir_list_size) {
        LOGI("All SM-DS events have been successfully processed");
    } else if (0 == *pir_list_size) {
        LOGE("[rsp__smds] Any event of the %u events registered in the SM-DS have been successfully processed", event_entry_list_size);
        M_free(*pir_list);
        *pir_list = NULL;
        *pir_list_size = 0;
        return eFatal;
    } else {
        LOGW("[rsp__smds] Only %u events of the %u events registered in the SM-DS have been successfully processed", *pir_list_size, event_entry_list_size);
    }

    return eOk;
}

ErrCode rsp__root_smds(es9_t* const es9, es10_t* const es10, es11_t* const es11, pir_t** pir_list, uint32_t* pir_list_size) {
    ErrCode rc;
    fqdn_t root_ds_address;

    /* Retrieve the root SM-DS Address */
    if ((rc = rsp__retrieve_euicc_root_ds_address(es10, &root_ds_address)) != eOk) {
        LOGE("[rsp__root_smds] Error on retrieve the rootDsAddress from the UICC, rc %d", rc);
        return rc;
    }

    /* Start the RSP procedure against the root SM-DS */
    return rsp__smds(es9, es10, es11, &root_ds_address, pir_list, pir_list_size);
}

ErrCode rsp__parse_activation_code(const uint8_t* activation_code, const uint32_t activation_code_len, activation_code_t* ac) {
    const uint8_t* ptr = activation_code;
    const uint8_t* first_out_of_bounds_ptr = activation_code + activation_code_len;

    if (!activation_code || activation_code_len == 0) {
        LOGE("[rsp__parse_activation_code] The activation code is empty or null");
        return eBadArg;
    }

    if (activation_code_len > ACTIVATION_CODE_MAX_SIZE) {
        LOGE("[rsp__parse_activation_code] The activation code is too long: size %lu, max size %u", activation_code_len, ACTIVATION_CODE_MAX_SIZE);
        return eBadArg;
    }

    LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] Activation code: ", activation_code, activation_code_len);

    /* Set default values */
    ac->ac_token = NULL;    // Is mandatory but MAY be zero-length
    ac->ac_token_size = 0;
    ac->smdp_oid = NULL;
    ac->smdp_oid_size = 0;
    ac->ccrf = false;

    // Check and if it's present skip, 'LPA:' prefix
    if (first_out_of_bounds_ptr - ptr >= ACTIVATION_CODE_PREFIX_LEN && 0 == memcmp(ptr, ACTIVATION_CODE_PREFIX, ACTIVATION_CODE_PREFIX_LEN)) {
        ptr += ACTIVATION_CODE_PREFIX_LEN;
        LOGT("[rsp__parse_activation_code] '%s' prefix found and skipped", ACTIVATION_CODE_PREFIX);
    }

    // Check AC_Format shall be 1
    if (first_out_of_bounds_ptr - ptr >= sizeof(char) && ACTIVATION_CODE_FORMAT == *ptr) {
        ptr++;
        LOGT("[rsp__parse_activation_code] AC_Format found and skipped");
    } else {
        LOG_UTF8_DATA(eLogErr, "[rsp__parse_activation_code] AC_Format not found on the AC: ", activation_code, activation_code_len);
        return eFatal;
    }

    // Check delimiter after AC Format
    if (first_out_of_bounds_ptr - ptr >= sizeof(char) && ACTIVATION_CODE_DELIMITER == *ptr) {
        ptr++;
        LOGT("[rsp__parse_activation_code] First delimiter found and skipped");
    } else {
        LOG_UTF8_DATA(eLogErr, "[rsp__parse_activation_code] Delimiter after the AC_Format not found on the AC: ", activation_code, activation_code_len);
        return eFatal;
    }

    // SMDP+ address
    ac->smdp_address = ptr;
    if ((ptr = memchr(ptr, ACTIVATION_CODE_DELIMITER, first_out_of_bounds_ptr - ptr))) {
        ac->smdp_address_size = (uint8_t) (ptr - ac->smdp_address);
        if (ac->smdp_address_size > 0) {
            LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] SMDP+ address: ", ac->smdp_address, ac->smdp_address_size);
            ptr++;
        } else {
            LOGE("[rsp__parse_activation_code] The SMDP+ address can not be zero-length");
            return eFatal;
        }
    } else {
        LOGE("[rsp__parse_activation_code] Delimiter after the SMDP+ address not found");
        return eFatal;
    }

    // AC_Token
    if (0 == first_out_of_bounds_ptr - ptr) {
        LOGD("[rsp__parse_activation_code] The AC_Token is zero-length");
        return eOk;
    }
    ac->ac_token = ptr;
    if ((ptr = memchr(ptr, ACTIVATION_CODE_DELIMITER, first_out_of_bounds_ptr - ptr))) {
        LOGT("[rsp__parse_activation_code] Delimiter after the AC_Token found");
        ac->ac_token_size = (uint8_t) (ptr - ac->ac_token);
        if (ac->ac_token_size > 0) {
            LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] AC_Token: ", ac->ac_token, ac->ac_token_size);
        } else {
            ac->ac_token = NULL;
            LOGD("[rsp__parse_activation_code] The AC_Token is zero-length");
        }
        ptr++;
    } else {
        LOGT("[rsp__parse_activation_code] Delimiter after the AC_Token not found");
        ac->ac_token_size = (uint8_t) (first_out_of_bounds_ptr - ac->ac_token);
        if (ac->ac_token_size > 0) {
            LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] AC_Token: ", ac->ac_token, ac->ac_token_size);
        } else {
            ac->ac_token = NULL;
            LOGD("[rsp__parse_activation_code] The AC_Token is zero-length");
        }
        return eOk;
    }

    // SM-DP+ OID
    if (0 == first_out_of_bounds_ptr - ptr) {
        LOGD("[rsp__parse_activation_code] The SM-DP+ OID is zero-length");
        return eOk;
    }
    ac->smdp_oid = ptr;
    if ((ptr = memchr(ptr, ACTIVATION_CODE_DELIMITER, first_out_of_bounds_ptr - ptr))) {
        LOGT("[rsp__parse_activation_code] Delimiter after the SM-DP+ OID found");
        ac->smdp_oid_size = (uint8_t) (ptr - ac->smdp_oid);
        if (ac->smdp_oid_size > 0) {
            LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] SM-DP+ OID: ", ac->smdp_oid, ac->smdp_oid_size);
        } else {
            ac->smdp_oid = NULL;
            LOGD("[rsp__parse_activation_code] The SM-DP+ OID is zero-length");
        }
        ptr++;
    } else {
        LOGT("[rsp__parse_activation_code] Delimiter after the SM-DP+ OID not found");
        ac->smdp_oid_size = (uint8_t) (first_out_of_bounds_ptr - ac->smdp_oid);
        if (ac->smdp_oid_size > 0) {
            LOG_UTF8_DATA(eLogDebug, "[rsp__parse_activation_code] SM-DP+ OID: ", ac->smdp_oid, ac->smdp_oid_size);
        } else {
            ac->smdp_oid = NULL;
            LOGD("[rsp__parse_activation_code] The SM-DP+ OID is zero-length");
        }
        return eOk;
    }
    // Confirmation Code Required Flag
    if (first_out_of_bounds_ptr - ptr > 0 &&  ACTIVATION_CODE_CC_REQUIRED_FLAG == *ptr) {
        LOGD("[rsp__parse_activation_code] Confirmation Code Required Flag is present");
        ac->ccrf = true;
    } else {
        LOGD("[rsp__parse_activation_code] Confirmation Code Required Flag is not present");
    }

    return eOk;
}

ErrCode rsp__utf8_to_fqdn(const uint8_t* ptr, uint32_t size, fqdn_t* fqdn) {
    /* Check UTF8 FQDN format */
    if (!ptr || 0 == size) {
        LOGE("[rsp__utf8_to_fqdn] The UTF8 FQDN is empty/null");
        return eBadArg;
    }
    if (size >= sizeof(fqdn->fqdn)) {
        LOGE("[rsp__utf8_to_fqdn] The UTF8 FQDN is too long. Current length: %u, max length: %u", size, sizeof(fqdn->fqdn) - 1);
        return eBadArg;
    }

    /* Copy the UTF-8 FQDN to the FQDN datatype */
    memcpy(fqdn->fqdn, ptr, size);
    fqdn->fqdn[size] = '\0';

    return eOk;
}

void rsp__free_pir(pir_t* pir) {
    M_free(pir->pir);
    pir->pir = NULL;
    pir->pir_size = 0;
}

void rsp__free_pir_list(pir_t** pir_list, uint32_t* pir_list_size) {
    uint32_t i;

    for (i = 0; i < *pir_list_size; i++) {
        rsp__free_pir(&(*pir_list)[i]);
    }

    M_free(*pir_list);
    *pir_list = NULL;
    pir_list_size = 0;
}

#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
ErrCode rsp__immediate_profile_enabling(es10_t* const es10) {
    ErrCode rc;
    int err;
    uint8_t* immediate_enable_response_tlv;
    uint32_t immediate_enable_response_tlv_size;
    immediate_enable_request_t immediate_enable_req = {
        .refresh_flag = REFRESH_FLAG
    };
    immediate_enable_response_t immediate_enable_response;

    /* Execute the ES10.ImmediateEnable */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__immediate_profile_enabling] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__immediate_enable(es10, &immediate_enable_req, &immediate_enable_response_tlv, &immediate_enable_response_tlv_size)) < 0) {
        LOGE("[rsp__immediate_profile_enabling] ES10.ImmediateEnabling failed, err %d", err); 
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__immediate_profile_enabling] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__immediate_profile_enabling] Error on immediate profile enabling");
        return eFatal;
    }

    /* Extract the result */
    rc = es10_tlv_extractor__immediate_enable_response(immediate_enable_response_tlv, immediate_enable_response_tlv_size, &immediate_enable_response);
    M_free(immediate_enable_response_tlv);
    immediate_enable_response_tlv = NULL;
    immediate_enable_response_tlv_size = 0;
    if (rc != eOk) {
        LOGE("[rsp__immediate_profile_enabling] Error extracting the result from the ImmediateEnableResponse, rc %d", rc);
        return rc;
    }

    /* Print the result */
    if (IMMEDIATE_ENABLE_RESULT_OK == immediate_enable_response.immediate_enable_result) {
        LOGI("Profile enabled using the immediate profile enabling");
        return eOk;
    } else {
        LOGE("[rsp__immediate_profile_enabling] Error immediate enabling the profile immediateEnableResult(%s)", STR_IMMEDIATE_ENABLE_RESULT_ERROR(immediate_enable_response.immediate_enable_result));
        return eFatal;
    }
}
#endif

static ErrCode rsp__profile_download_and_installation(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, bool is_default_dp, const uint8_t* matching_id, const uint8_t matching_id_len, const bool ccrf, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir) {
    ErrCode rc;
    authenticate_client_response_es9_t authenticate_client_response;
    rsp_result_t rsp_result;
    LOGI("Starting the Procedure Profile Download and Installation");
    
    /* Check input parameters */
    if (ccrf && (!confirmation_code || 0 == confirmation_code_len)) {
        LOGE("[rsp__profile_download_and_installation] No Confirmation Code has been provided for a RSP that has the Confirmation Code Required Flag enabled.");
        return eBadArg;
    }

    /* Log input parameters */
    rsp__fqdn_to_lowercase(smdp_address);
    LOGD("[rsp__profile_download_and_installation] RSP SMDP+ address: %s", smdp_address->fqdn);
    if (matching_id && matching_id_len > 0) {
        LOG_UTF8_DATA(eLogDebug, "[rsp__profile_download_and_installation] MatchingId: ", matching_id, matching_id_len);
    }
    if (ccrf) {
        LOG_UTF8_DATA(eLogDebug, "[rsp__profile_download_and_installation] ConfirmationCode: %s", confirmation_code, confirmation_code_len);
    }

    /* Initial user consent (if there is already an enabled Profile with PPR1 set) */
    if ((rc = rsp__initial_user_consent(es10)) != eOk) {
        LOGE("[rsp__profile_download_and_installation] Initial user consent failed, rc %d", rc);
        return rc;
    }

    /* Mutual Authentication against the SMDP+ */
    if ((rc = mutual_authentication__smdp(es9, es10, smdp_address, matching_id, matching_id_len, &authenticate_client_response)) != eOk) {
        LOGE("[rsp__profile_download_and_installation] Error on mutual authentication, rc %d", rc);
        return rc;
    }

    /* Check if the AuthenticateClientResponseEs9 is an error response */
    if (authenticate_client_response.choice == AUTHENTICATE_CLIENT_ERROR_CHOICE) {
        LOGE("[rsp__profile_download_and_installation] The AuthenticateClientResponseEs9 has an authenticateClientError(%d)", authenticate_client_response.value.error);
        return eFatal;
    }

    /* Check ProfileMetadata */
    if ((rc = rsp__profile_can_be_downloaded(es10, authenticate_client_response.value.ok.profile_metadata, authenticate_client_response.value.ok.profile_metadata_size, &rsp_result)) != eOk) {
        LOGE("[rsp__profile_download_and_installation] Error checking if the profile can be downloaded, rc %d", rc);
        rsp_result.choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        rsp_result.cancel_session_reason = CANCEL_SESSION_REASON_UNDEFINED_REASON;
    }

    /* Execute download confirmation or download rejection */
    if (RSP_RESULT_CHOICE_OK == rsp_result.choice) {
        // Continue with RSP flow
        return rsp__download_confirmation(es9, es10, smdp_address, is_default_dp, confirmation_code, confirmation_code_len, &authenticate_client_response, pir);
    } else {
        // Execute Cancel Session
        rsp__download_rejection(es9, es10, smdp_address, &authenticate_client_response.value.ok.transaction_id, rsp_result.cancel_session_reason);
        es9__free_authenticate_client_response(&authenticate_client_response);
        return eFatal;
    }
}

static ErrCode rsp__download_rejection(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, const transaction_id_t* transaction_id, const cancel_session_reason_t reason) {
    int err;
    ErrCode rc;
    cancel_session_request_t cancel_session_request_es10 = { 0 };
    cancel_session_request_es9_t cancel_session_request_es9 = { 0 };
    cancel_session_response_es9_t cancel_session_response_es9 = { 0 };
    LOGI("Starting the Sub-procedure Profile Download and Installation - Download Rejection");

    /* Check input parameters */
    if (!transaction_id) {
        LOGE("[rsp__download_rejection] The TransactionId is null");
        return eBadArg;
    }

    /* Execute the ES10.CancelSession */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__download_rejection] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    memcpy(&cancel_session_request_es10.transaction_id, transaction_id, sizeof(transaction_id_t));
    cancel_session_request_es10.reason = reason;
    if ((err = es10__cancel_session(es10, &cancel_session_request_es10, &cancel_session_request_es9.cancel_session_response, &cancel_session_request_es9.cancel_session_response_size)) < 0) {
        LOGE("[rsp__download_rejection] ES10.CancelSession failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__download_rejection] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__download_rejection] Error on Cancel the Session against the UICC");
        return eFatal;
    }

    /* Execute the ES9.CancelSession */
    memcpy(&cancel_session_request_es9.transaction_id, transaction_id, sizeof(transaction_id_t)); // Copy the TransactionId
    rc = es9__cancel_session(es9, smdp_address->fqdn, &cancel_session_request_es9, &cancel_session_response_es9);
    M_free(cancel_session_request_es9.cancel_session_response);
    cancel_session_request_es9.cancel_session_response = NULL;
    cancel_session_request_es9.cancel_session_response_size = 0;
    if (rc != eOk) {
        LOGE("[rsp__download_rejection] ES9.CancelSession failed, rc %d", rc);
        return rc;
    }

    /* Handle the response */
    switch (cancel_session_response_es9.choice)
    {
    case CANCEL_SESSION_OK:
        LOGD("[rsp__download_rejection] CancelSessionResponseEs9 is cancelSessionOk");
        return eOk;
    case CANCEL_SESSION_ERROR:
        LOGE("[rsp__download_rejection] CancelSessionResponseEs9 is cancelSessionError(%s)", STR_CANCEL_SESSION_ERROR(cancel_session_response_es9.error));
        return eFatal;
    default:
        LOGE("[rsp__download_rejection] Unknown CancelSessionResponseEs9 choice %d", cancel_session_response_es9.choice);
        return eFatal;
    }
}

// This function is responsible for freeing the authenticate_client_response parameter regardless of its result.
static ErrCode rsp__download_confirmation(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, bool is_default_dp, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, authenticate_client_response_es9_t* authenticate_client_response, pir_t* pir) {
    ErrCode rc;
    get_bound_profile_package_response_t get_bound_profile_package_response;
    transaction_id_t transaction_id;
    rsp_prepare_download_result_t rsp_prepare_download_result;
    rsp_profile_installation_result_t rsp_profile_installation_result;
    rsp_result_t rsp_result;
    LOGI("Starting the Sub-procedure Profile Download and Installation - Download Confirmation");

    /* Check input parameters */
    if (!pir) {
        LOGE("[rsp__download_confirmation] PIR object is null");
        es9__free_authenticate_client_response(authenticate_client_response);
        return eBadArg;
    }
    if (authenticate_client_response->choice == AUTHENTICATE_CLIENT_ERROR_CHOICE) {
        LOGE("[rsp__download_confirmation] The AuthenticateClientResponseEs9 has an authenticateClientError(%d).", authenticate_client_response->value.error);
        es9__free_authenticate_client_response(authenticate_client_response);
        return eBadArg;
    }

    memcpy(&transaction_id, &authenticate_client_response->value.ok.transaction_id, sizeof(transaction_id_t));

    /* Prepare Download */
    rc = rsp__prepare_download(es9, es10, smdp_address->fqdn, authenticate_client_response, confirmation_code, confirmation_code_len, &rsp_prepare_download_result);
    es9__free_authenticate_client_response(authenticate_client_response);
    if (rc != eOk) {
        LOGE("[rsp__download_confirmation] Error on Prepare Download, rc %d", rc);
        rsp_prepare_download_result.choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        rsp_prepare_download_result.value.cancel_session_reason = CANCEL_SESSION_REASON_UNDEFINED_REASON;
    }
    // Check if cancel session is need it
    if (RSP_RESULT_CHOICE_CANCEL_SESSION == rsp_prepare_download_result.choice) {
        rsp__download_rejection(es9, es10, smdp_address, &transaction_id, rsp_prepare_download_result.value.cancel_session_reason);
        return eFatal;
    }

    /* Get Bound Profile Package */
    rc = es9__get_bound_profile_package(es9, smdp_address->fqdn, &rsp_prepare_download_result.value.get_bound_profile_package_request, &get_bound_profile_package_response);
    rsp__free_get_bound_profile_package_request(&rsp_prepare_download_result.value.get_bound_profile_package_request);
    if (rc != eOk) {
        LOGE("[rsp__download_confirmation] Error downloading the Bound Profile Package from the SMDP+, rc %d", rc);
        return rc;
    }

    if (GET_BOUND_PROFILE_PACKAGE_ERROR == get_bound_profile_package_response.choice) {
        LOGE("[rsp__download_confirmation] The GetBoundProfilePackageResponse has an getBoundProfilePackageError(%d).", get_bound_profile_package_response.value.error);
        es9__free_get_bound_profile_package_response(&get_bound_profile_package_response);
        return eFatal;
    }

    /* Verify Metadata */
    if ((rc = rsp__verify_profile_metadata(es10, get_bound_profile_package_response.value.ok.bound_profile_package, get_bound_profile_package_response.value.ok.bound_profile_package_size, &rsp_result)) != eOk) {
        LOGE("[rsp__download_confirmation] Verification of profileMetadata failed, rc %d", rc);
        rsp_result.choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        rsp_result.cancel_session_reason = CANCEL_SESSION_REASON_UNDEFINED_REASON;
    }

    // Check if cancel session is need it
    if (RSP_RESULT_CHOICE_CANCEL_SESSION == rsp_result.choice) {
        rsp__download_rejection(es9, es10, smdp_address, &transaction_id, rsp_result.cancel_session_reason);
        return eFatal;
    }

    /* Execute profile installation */
    if ((rc = rsp__profile_installation(es9, es10, is_default_dp, &get_bound_profile_package_response, &rsp_profile_installation_result)) != eOk) {
        LOGE("[rsp__download_confirmation] Profile installation failed, rc %d", rc);
        rsp_profile_installation_result.choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        rsp_profile_installation_result.value.cancel_session_reason = CANCEL_SESSION_REASON_UNDEFINED_REASON;
    }

    // Check if cancel session is need it
    if (RSP_RESULT_CHOICE_CANCEL_SESSION == rsp_profile_installation_result.choice) {
        rsp__download_rejection(es9, es10, smdp_address, &transaction_id, rsp_profile_installation_result.value.cancel_session_reason);
        return eFatal;
    }
    
    // Copy the PIR result
    memcpy(pir, &rsp_profile_installation_result.value.pir, sizeof(pir_t));

    return rc;
}

// This function is responsible for freeing the get_bpp_response parameter regardless of its result.
static ErrCode rsp__profile_installation(es9_t* const es9, es10_t* const es10, bool is_default_dp, get_bound_profile_package_response_t* get_bpp_response, rsp_profile_installation_result_t* result) {
    ErrCode rc;
    LOGI("Starting the Sub-procedure Profile Installation");

    if (!result) {
        LOGE("[rsp__profile_installation] result object is null");
        es9__free_get_bound_profile_package_response(get_bpp_response);
        return eBadArg;
    }
    result->choice = RSP_RESULT_CHOICE_OK;

    if (GET_BOUND_PROFILE_PACKAGE_ERROR == get_bpp_response->choice) {
        LOGE("[rsp__profile_installation] The GetBoundProfilePackageResponse has an getBoundProfilePackageError(%d).", get_bpp_response->value.error);
        es9__free_get_bound_profile_package_response(get_bpp_response);
        return eFatal;
    }

    /* Install the Bound Profile Package */
    rc = rsp__load_bound_profile_package(es10, get_bpp_response->value.ok.bound_profile_package, get_bpp_response->value.ok.bound_profile_package_size, &result->value.pir.pir, &result->value.pir.pir_size);
    es9__free_get_bound_profile_package_response(get_bpp_response);
    if (rc != eOk) {
        LOGE("[rsp__profile_installation] Error on load the BPP, rc %d", rc);
        result->choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        result->value.cancel_session_reason = CANCEL_SESSION_REASON_LOAD_BPP_EXECUTION_ERROR;
        return eOk;
    }

#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
    result->value.pir.immediate_profile_enabled = false;
    if (is_default_dp) {
        ErrCode send_notification_rc;

        /* Send the Profile Installation Result to the SMDP+ */
        if ((send_notification_rc = notifications_delivery__single_notification(es9, es10, false, result->value.pir.pir, result->value.pir.pir_size)) != eOk) {
            LOGW("[rsp__profile_installation] Error on send the ProfileInstallationResult notification to the SMDP+, rc %d", send_notification_rc);
        }

        /* Execute immediate profile enabling */
        if (eOk == (rc = rsp__immediate_profile_enabling(es10))) {
            LOGD("[rsp__profile_installation] Immediate Profile enabled");
            result->value.pir.immediate_profile_enabled = true;
        } else {
            LOGW("[rsp__profile_installation] Error on immediate Profile enabling, rc %d", rc);
        }

        /* Remove the PIR notification from the UICC */
        if (eOk == send_notification_rc) {
            if ((rc = notifications_delivery__remove_pending_notification(es10, result->value.pir.pir, result->value.pir.pir_size)) != eOk) {
                LOGW("[rsp__profile_installation] Error on remove the ProfileInstallationResult notification, rc %d", rc);
            }
        }

        /* Deliver all the other pending notifications (generated on the immediate profile enabling) */
        if ((rc = notifications_delivery__all_notifications(es9, es10)) != eOk) {
            LOGW("[rsp__profile_installation] Error delivering the pending notifications, rc %d", rc);
        }
    } else {
#endif
        if ((rc = notifications_delivery__single_notification(es9, es10, true, result->value.pir.pir,result->value.pir.pir_size)) != eOk) {
            LOGW("[rsp__profile_installation] Error delivering the ProfileInstallationResult notification, rc %d", rc);
        }
#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
    }
#endif

    return eOk;
}

static ErrCode rsp__prepare_download(es9_t* const es9, es10_t* const es10, const char* smdp_address, authenticate_client_response_es9_t* authenticate_client_response, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, rsp_prepare_download_result_t* result) {
    int err;
    ErrCode rc;
    smdp_signed_2_t smdp_signed_2;
    prepare_download_request_t prepare_download_request = { 0 };

    if (!result) {
        LOGE("[rsp__prepare_download] result object is null");
        return eBadArg;
    }
    result->choice = RSP_RESULT_CHOICE_OK;

    /* Check if the AuthenticateClientResponseEs9 is an error response */
    if (authenticate_client_response->choice == AUTHENTICATE_CLIENT_ERROR_CHOICE) {
        LOGE("[rsp__prepare_download] The AuthenticateClientResponseEs9 has an authenticateClientError(%d). Aborting the Remote Sim Provisioning procedure", authenticate_client_response->value.error);
        return eBadArg;
    }

    /* Check if the Confirmation Code is required */
    if ((rc = es10_tlv_extractor__smdp_signed_2(authenticate_client_response->value.ok.smdp_signed_2, authenticate_client_response->value.ok.smdp_signed_2_size, &smdp_signed_2)) != eOk) {
        LOGE("[rsp__prepare_download] Error extracting data from the smdpSigned2 of the AuthenticateClientResponseEs9, rc %d", rc);
        return rc;
    }
    if (smdp_signed_2.cc_required_flag && (!confirmation_code || 0 == confirmation_code_len)) {
        LOGE("[rsp__prepare_download] No Confirmation Code has been provided for a Profile that has the Confirmation Code Required Flag enabled (in the smdpSigned2). Please enter a Confirmation Code when starting the Remote Provisioning for this Profile.");
        result->choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
        result->value.cancel_session_reason = CANCEL_SESSION_REASON_POSTPONED; // Since we have not implemented an LPAd prompt, this is the reason we have found most suitable.
        return eOk;
    }

    /* Prepare the PrepareDownloadRequest */
    prepare_download_request.smdp_signed_2 = authenticate_client_response->value.ok.smdp_signed_2;
    prepare_download_request.smdp_signed_2_size = authenticate_client_response->value.ok.smdp_signed_2_size;
    prepare_download_request.smdp_signature_2 = authenticate_client_response->value.ok.smdp_signature_2;
    prepare_download_request.smdp_signature_2_size = authenticate_client_response->value.ok.smdp_signature_2_size;
    prepare_download_request.field_is_present.hash_cc = smdp_signed_2.cc_required_flag;
    if (prepare_download_request.field_is_present.hash_cc) {
        /* Calculate the Hash of the Confirmation Code */
        if ((rc = rsp__calculate_hash_confirmation_code(&smdp_signed_2, confirmation_code, confirmation_code_len, &prepare_download_request.hash_cc)) != eOk) {
            LOGE("[rsp__prepare_download] Error calculating the hash of the Confirmation Code, rc %d", rc);
            return rc;
        }
    }
    prepare_download_request.smdp_certificate = authenticate_client_response->value.ok.smdp_certificate;
    prepare_download_request.smdp_certificate_size = authenticate_client_response->value.ok.smdp_certificate_size;

    /* Send the PrepareDownloadRequest */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__prepare_download] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__prepare_download(es10, &prepare_download_request, &result->value.get_bound_profile_package_request.prepare_download_response, &result->value.get_bound_profile_package_request.prepare_download_response_size)) < 0) {
        LOGE("[rsp__prepare_download] ES10.PrepareDownload failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__prepare_download] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__prepare_download] Error on Prepare Download");
        return eFatal;
    }

    /* Copy the transactionId of the AuthenticateClientResponseEs9 to the GetBoundProfilePackageRequest */
    memcpy(&result->value.get_bound_profile_package_request.transaction_id, &authenticate_client_response->value.ok.transaction_id, sizeof(transaction_id_t));

    return eOk;
}

static ErrCode rsp__load_bound_profile_package(es10_t* const es10, const uint8_t* bpp, uint32_t bpp_size, uint8_t** pir, uint32_t* pir_size) {
    int err;

    /* Check input parameters */
    if (!bpp || 0 == bpp_size) {
        LOGE("[rsp__load_bound_profile_package] The BoundProfilePackage is empty/null");
        return eBadArg;
    }

    /* ES10.LoadBoundProfilePackage */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__load_bound_profile_package] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__load_bound_profile_package(es10, bpp, bpp_size, pir, pir_size)) < 0) {
        LOGE("[rsp__load_bound_profile_package] ES10.LoadBoundProfilePackage failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__load_bound_profile_package] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__load_bound_profile_package] Error on Install the Profile");
        return eFatal;
    }

    return eOk;
}

static ErrCode rsp__initial_user_consent(es10_t* const es10) {
    ErrCode rc;
    bool is_profile_enabled;
    profile_info_t profile_info;

    if ((rc = rsp__retrieve_enabled_profile(es10, &is_profile_enabled, &profile_info)) != eOk) {
        LOGE("[rsp__initial_user_consent] Error retrieving the data of the enabled profile (if any), rc %d", rc);
        return rc;
    }

    /* If there is no enabled profile */
    if (!is_profile_enabled) {
        LOGD("[rsp__initial_user_consent] There is no profile enabled, it is not needed to ask for the user consent before starting the RSP.");
        return eOk;
    }

    /* If there is an enabled profile */
    if (profile_info.field_is_present.profile_policy_rules && profile_info.profile_policy_rules.ppr1) {
        // End user consent needed
#ifdef SUPPORT_USER_CONSENT_INTERFACE
        if (USER_CONSENT_ACCEPTED == user_consent__request(INITIAL_USER_CONSENT_STR, USER_CONSENT_TIMEOUT_VALUE)) {
            LOGD("[rsp__initial_user_consent] Initial user consent accepted.");
            return eOk;
        } else {
            LOGE("[rsp__initial_user_consent] Initial user consent not accepted.");
            return eFatal;
        }
#else
        LOGD("[rsp__initial_user_consent] There is already an enabled Profile with PPR1 (Disabling of this Profile is not allowed). User consent skipped since is not supported");
        return eOk;
#endif
    } else {
        // End user consent not needed
        LOGD("[rsp__initial_user_consent] The enabled profile does not have the PPR1 set, it is not needed to ask the for user consent before starting the RSP.");
        return eOk;
    }
}

static ErrCode rsp__profile_can_be_downloaded(es10_t* const es10, const uint8_t* profile_metadata, uint32_t profile_metadata_size, rsp_result_t* result) {
    ErrCode rc;
    profile_info_t profile_info;
    ppr_verification_result_t ppr_verification_result;

    if (!result) {
        LOGE("[rsp__profile_can_be_downloaded] result object is null");
        return eBadArg;
    }
    result->choice = RSP_RESULT_CHOICE_CANCEL_SESSION;
    result->cancel_session_reason = CANCEL_SESSION_REASON_UNDEFINED_REASON;

    // Parse the ProfileMetadata
    if ((rc = es10_tlv_extractor__store_metadata_request(profile_metadata, profile_metadata_size, &profile_info)) != eOk) {
        LOGE("[rsp__profile_can_be_downloaded] Error parsing the StoreMetadataRequest, rc %d", rc);
        return rc;
    }

    // Check Profile PPRs are allowed
    if ((rc = rsp__check_profile_pprs_are_allowed(es10, &profile_info, &ppr_verification_result)) != eOk) {
        LOGE("[rsp__profile_can_be_downloaded] Error checking if Profile PPRs are allowed, rc %d", rc);
        return rc;
    }

    if (PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED == ppr_verification_result.choice) {
        LOGE("[rsp__profile_can_be_downloaded] Profile PPRs are not allowed. The Sub-procedure of Download rejection will be triggered");
        result->cancel_session_reason = CANCEL_SESSION_REASON_PPR_NOT_ALLOWED;
        return eOk;
    }

    // Display the Profile for the download confirmation user consent
    es10_display__profile_info(&profile_info);
#ifdef SUPPORT_USER_CONSENT_INTERFACE
    user_consent_result_t user_consent_result;
    if (ppr_verification_result.ok.ppr1_user_consent_required && ppr_verification_result.ok.ppr2_user_consent_required) {
        // PPR1, PPR2 and Profile Download user consent
        user_consent_result = user_consent__request(PPR1_AND_PPR2_USER_CONSENT_STR, USER_CONSENT_TIMEOUT_VALUE);
    } else if (ppr_verification_result.ok.ppr1_user_consent_required) {
        // PPR1 and Profile Download user consent
        user_consent_result = user_consent__request(PPR1_USER_CONSENT_STR, USER_CONSENT_TIMEOUT_VALUE);
    } else if (ppr_verification_result.ok.ppr2_user_consent_required) {
        // PPR2 and Profile Download user consent
        user_consent_result = user_consent__request(PPR2_USER_CONSENT_STR, USER_CONSENT_TIMEOUT_VALUE);
    } else {
        // Only Profile Download user consent
        user_consent_result = user_consent__request(NO_PPR_USER_CONSENT_STR, USER_CONSENT_TIMEOUT_VALUE);
    }

    switch (user_consent_result)
    {
    case USER_CONSENT_TIMEOUT:
        result->cancel_session_reason = CANCEL_SESSION_REASON_TIMEOUT;
        break;
    case USER_CONSENT_ACCEPTED:
        result->choice = RSP_RESULT_CHOICE_OK;
        break;
    case USER_CONSENT_REJECTED:
        result->cancel_session_reason = CANCEL_SESSION_REASON_END_USER_REJECTION;
        break;
    case USER_CONSENT_POSTPONED:
        result->cancel_session_reason = CANCEL_SESSION_REASON_POSTPONED;
        break;
    default:
        LOGE("[rsp__profile_can_be_downloaded] Unknown end user consent result %d", user_consent_result);
        return eFatal;
    }
#else
    LOGD("[rsp__profile_can_be_downloaded] User consent for the profile metadata and PPRs skipped since user consent is not supported");
    result->choice = RSP_RESULT_CHOICE_OK;
#endif

    return eOk;
}

static ErrCode rsp__check_profile_pprs_are_allowed(es10_t* const es10, const profile_info_t* profile_info, ppr_verification_result_t* ppr_verification_result) {
    ErrCode rc;
    int err;
    uint8_t* profile_info_list_response_tlv = NULL;
    uint32_t profile_info_list_response_tlv_size = 0;
    uint8_t* get_rat_response_tlv = NULL;
    uint32_t get_rat_response_tlv_size = 0;
    uint32_t installed_operational_profiles = 0;
    profile_info_list_request_t profile_info_list_request = {
        .field_is_present = {
            .search_criteria = true,
            .tag_list = false
        },
        .search_criteria = {
            .choice = PROFILE_CLASS_PROFILE_INFO_LIST_CHOICE,
            .value = {
                .profile_class = PROFILE_CLASS_OPERATIONAL
            }
        }
    };
    profile_info_list_response_t profile_info_list_response;
    get_rat_response_t get_rat_response;

    /* Check input parameters */
    if (!profile_info) {
        LOGE("[rsp__check_profile_pprs_are_allowed] ProfileInfo object is null");
        return eBadArg;
    }
    if (!ppr_verification_result) {
        LOGE("[rsp__check_profile_pprs_are_allowed] PPR verification result object is null");
        return eBadArg;
    }

    // Default result (if any PPR needs to be verified)
    ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_OK;
    ppr_verification_result->ok.ppr1_user_consent_required = false;
    ppr_verification_result->ok.ppr2_user_consent_required = false;

    // Check if the ProfileMetadata contains PPR(s)
    if (!profile_info->field_is_present.profile_policy_rules) {
        LOGD("[rsp__check_profile_pprs_are_allowed] ProfileMetadata does not contain PPR(s).");
        return eOk;
    }
    LOGD("[rsp__check_profile_pprs_are_allowed] ProfileMetadata contains PPR(s).");

    // Retrieve the Rules Authorisation Table and GetProfilesInfo (if the ProfileMetadata contains PPR1)
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__check_profile_pprs_are_allowed] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__get_rat(es10, &get_rat_response_tlv, &get_rat_response_tlv_size)) < 0) {
        LOGE("[rsp__check_profile_pprs_are_allowed] ES10.GetRAT failed, err %d", err);
    }

    if (err >= 0 && profile_info->profile_policy_rules.ppr1) {
        LOGD("[rsp__check_profile_pprs_are_allowed] ProfileMetadata has the PPR1 set.");
        if ((err = es10__get_profiles_info(es10, &profile_info_list_request, &profile_info_list_response_tlv, &profile_info_list_response_tlv_size)) < 0) {
            LOGE("[rsp__check_profile_pprs_are_allowed] ES10.GetProfilesInfo failed, err %d", err);
            M_free(get_rat_response_tlv);
            get_rat_response_tlv = NULL;
            get_rat_response_tlv_size = 0;
        }
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__check_profile_pprs_are_allowed] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__check_profile_pprs_are_allowed] Error on retrieve the Rules Authorisation Table and ProfilesInfo, err %d", err);
        return eFatal;
    }

    // If the ProfileMetadata contains PPR1 and an Operational Profile is installed: PPR not allowed
    if (profile_info->profile_policy_rules.ppr1) {
        // As we have set the search criteria to filter by Operationl profiles, we only have to check if the list is empty or not.
        if ((rc = es10_tlv_extractor__profile_info_list_response(profile_info_list_response_tlv, profile_info_list_response_tlv_size, &profile_info_list_response)) != eOk) {
            LOGE("[rsp__check_profile_pprs_are_allowed] Error parsing the ProfileInfoListResponse, rc %d", rc);
            M_free(get_rat_response_tlv);
            M_free(profile_info_list_response_tlv);
            return rc;
        }

        if (PROFILE_INFO_LIST_ERROR_CHOICE == profile_info_list_response.choice) {
            LOGE("[rsp__check_profile_pprs_are_allowed] The ProfileInfoListResponse is a profileInfoListError, rc %d", rc);
            M_free(get_rat_response_tlv);
            M_free(profile_info_list_response_tlv);
            return rc;
        }

        rc = tlv_data_extractor__asn1_list_size(&profile_info_list_response.value.ok, &installed_operational_profiles);
        M_free(profile_info_list_response_tlv);
        profile_info_list_response_tlv = NULL;
        profile_info_list_response_tlv_size = 0;
        if (rc != eOk) {
            LOGE("[rsp__check_profile_pprs_are_allowed] Error counting the number of installed Operational Profiles, rc %d", rc);
            M_free(get_rat_response_tlv);
            return rc;
        }

        if (installed_operational_profiles > 0) {
            LOGE("[rsp__check_profile_pprs_are_allowed] The ProfileMetadata contains PPR1 and %u Operational Profile(s) is/are installed.", installed_operational_profiles);
            ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED;
            M_free(get_rat_response_tlv);
            return eOk;
        }
    }

    if (!profile_info->field_is_present.profile_owner) { // Case to discuss
        LOGE("[rsp__check_profile_pprs_are_allowed] The ProfileOwner is not present in the ProfileMetadata");
        ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED;
        M_free(get_rat_response_tlv);
        return eOk;
    }

    // Parse the GetRatResponse
    if ((rc = es10_tlv_extractor__get_rat_response(get_rat_response_tlv, get_rat_response_tlv_size, &get_rat_response)) != eOk) {
        LOGE("[rsp__check_profile_pprs_are_allowed] Error parsing the GetRatResponse, rc %d", rc);
        M_free(get_rat_response_tlv);
        return rc;
    }
    
    // Verify the PPRS against RAT
    rc = ppr_verfication__verify_profile_pprs(&profile_info->profile_owner, &profile_info->profile_policy_rules, &get_rat_response, ppr_verification_result);
    M_free(get_rat_response_tlv);
    get_rat_response_tlv = NULL;
    get_rat_response_tlv_size = 0;

    return rc;
}

static ErrCode rsp__verify_profile_metadata(es10_t* const es10, const uint8_t* profile_metadata, uint32_t profile_metadata_size, rsp_result_t* result) {
    if (!result) {
        LOGE("[rsp__verify_profile_metadata] result object is null");
        return eBadArg;
    }

    /** TODO: Verify ProfileMetadata */
    result->choice = RSP_RESULT_CHOICE_OK;

    return eOk;
}

static ErrCode rsp__calculate_hash_confirmation_code(const smdp_signed_2_t* smdp_signed_2, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, sha256_hash_t* hash_cc) {
    uint8_t aux[SHA256_BLOCK_SIZE + TRANSACION_ID_MAX_SIZE];
    uint8_t aux_size;
    sha_256_ctx_t sha256_context;

    if (!smdp_signed_2->cc_required_flag) {
        LOGE("[rsp__calculate_hash_confirmation_code] The ccRequiredFlag has a false value in the SmdpSigned2");
        return eBadArg;
    }

    // SHA256 (Confirmation Code)
    LOG_UTF8_DATA(eLogDebug, "[rsp__calculate_hash_confirmation_code] Confirmation Code: '%s'", confirmation_code, confirmation_code_len);
    sha256_init(&sha256_context);
    sha256_update(&sha256_context, (uint8_t*) confirmation_code, (size_t) confirmation_code_len);
    sha256_final(&sha256_context, hash_cc);
    LOG_DATA(eLogDebug, "[rsp__calculate_hash_confirmation_code] SHA256 (Confirmation Code)", hash_cc->hash, sizeof(hash_cc->hash));
    // SHA256 (Confirmation Code) | TransactionID
    memcpy(aux, hash_cc->hash, sizeof(hash_cc->hash));
    memcpy(aux + sizeof(hash_cc->hash), smdp_signed_2->transaction_id.transaction_id, smdp_signed_2->transaction_id.transaction_id_size);
    aux_size = sizeof(hash_cc->hash) + smdp_signed_2->transaction_id.transaction_id_size;
    LOG_DATA(eLogDebug, "[rsp__calculate_hash_confirmation_code] SHA256 (Confirmation Code) | TransactionID", aux, aux_size);
    // SHA256 (SHA256 (Confirmation Code) | TransactionID)
    sha256_init(&sha256_context);
    sha256_update(&sha256_context, (uint8_t*) aux, aux_size);
    sha256_final(&sha256_context, hash_cc);
    LOG_DATA(eLogDebug, "[rsp__calculate_hash_confirmation_code] SHA256 (SHA256 (Confirmation Code) | TransactionID)", hash_cc->hash, sizeof(hash_cc->hash));

    return eOk;
}

static ErrCode rsp__retrieve_euicc_default_dp_address(es10_t* const es10, fqdn_t* default_dp_address) {
    euicc_configured_addresses_response_t euicc_addresses;
    ErrCode rc;

    /* Retreieve the configured addresses */
    if ((rc = rsp__retrieve_euicc_configured_addresses(es10, &euicc_addresses)) != eOk) {
        LOGE("[rsp__retrieve_euicc_default_dp_address] Error on retrieve the default SM-DP+ Address from the UICC, rc %d", rc);
        return rc;
    }

    /* Check if the defaultDpAddress is configured */
    if (!euicc_addresses.field_is_present.default_dp_address) {
        LOGE("[rsp__retrieve_euicc_default_dp_address] The defaultDpAddress is not configured on the UICC");
        return eFatal;
    }

    memcpy(default_dp_address, &euicc_addresses.default_dp_address, sizeof(fqdn_t)); // Copy the defaultDpAddress to the output parameter

    return eOk;
}

static ErrCode rsp__retrieve_euicc_root_ds_address(es10_t* const es10, fqdn_t* root_ds_address) {
    euicc_configured_addresses_response_t euicc_addresses;
    ErrCode rc;

    /* Retreieve the configured addresses */
    if ((rc = rsp__retrieve_euicc_configured_addresses(es10, &euicc_addresses)) != eOk) {
        LOGE("[rsp__retrieve_euicc_root_ds_address] Error on retrieve the root SM-DS Address from the UICC, rc %d", rc);
        return rc;
    }

    memcpy(root_ds_address, &euicc_addresses.root_ds_address, sizeof(fqdn_t)); // Copy the rootDsAddress to the output parameter

    return eOk;
}

static ErrCode rsp__retrieve_euicc_configured_addresses(es10_t* const es10, euicc_configured_addresses_response_t* euicc_addresses) {
    int err;
    ErrCode rc;
    uint8_t* configured_addresses;
    uint32_t configured_addresses_size;

    /* Send the ES10.GetEuiccConfiguredAddresses */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__retrieve_euicc_configured_addresses] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__get_euicc_configured_addresses(es10, &configured_addresses, &configured_addresses_size)) < 0) {
        LOGE("[rsp__retrieve_euicc_configured_addresses] ES10.GetEuiccConfiguredAddresses failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__retrieve_euicc_configured_addresses] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__retrieve_euicc_configured_addresses] Error on retrieve the eUICC Addresses, err %d", err);
        return eFatal;
    }

    /* Extract the Addresses from the EuiccConfiguredAddressesResponse */
    rc = es10_tlv_extractor__euicc_configured_addresses_response(configured_addresses, configured_addresses_size, euicc_addresses);
    M_free(configured_addresses);
    configured_addresses = NULL;
    configured_addresses_size = 0;
    if (rc != eOk) {
        LOGE("[rsp__retrieve_euicc_configured_addresses] Error extracting the eUICC Addresses from the EuiccConfiguredAddressesResponse, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode rsp__retrieve_enabled_profile(es10_t* const es10, bool* is_profile_enabled, profile_info_t* obj) {
    int err;
    ErrCode rc;
    uint8_t* response;
    uint32_t response_size;
    profile_info_list_request_t request = {
        .field_is_present = {
            .search_criteria = false, // Should we search only the operational profiles?
            .tag_list = true
        },
        .tag_list = {
            .iccid = false,
            .isdp_aid = false,
            .profile_state = true,
            .profile_nickname = false,
            .service_provider_name = false,
            .profile_name = false,
            .icon_type = false,
            .icon = false,
            .profile_class = false,
            .notification_configuration_info = false,
            .profile_owner = false,
            .smdp_propietary_data = false,
            .profile_policy_rules = true
        }
    };

    /* Send the ES10.GetProfilesInfo */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[rsp__retrieve_enabled_profile] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__get_profiles_info(es10, &request, &response, &response_size)) < 0) {
        LOGE("[rsp__retrieve_enabled_profile] ES10.GetProfilesInfo failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[rsp__retrieve_enabled_profile] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[rsp__retrieve_enabled_profile] Error on retrieve the eUICC Profiles, err %d", err);
        return eFatal;
    }

    /* Extract the Enabled Profile from the ProfileInfoListResponse */
    rc = es10_tlv_extractor__profile_info_enabled_profile(response, response_size, is_profile_enabled, obj);
    M_free(response);
    response = NULL;
    response_size = 0;
    if (rc != eOk) {
        LOGE("[rsp__retrieve_enabled_profile] Error extracting the enabled profile from the ProfileInfoListResponse, rc %d", rc);
        return rc;
    }

    return eOk;
}

static void rsp__free_get_bound_profile_package_request(get_bound_profile_package_request_t* get_bound_profile_package_request) {
    M_free(get_bound_profile_package_request->prepare_download_response);
    get_bound_profile_package_request->prepare_download_response = NULL;
    get_bound_profile_package_request->prepare_download_response_size = 0;
}

static void rsp__fqdn_to_lowercase(fqdn_t* fqdn) {
    size_t fqdn_len = strlen(fqdn->fqdn);
    size_t i;

    for (i = 0; i < fqdn_len; i++) {
        fqdn->fqdn[i] = tolower(fqdn->fqdn[i]);
    }
}
