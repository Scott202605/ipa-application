/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa_display.h"

#include <stdio.h>
#include "log.h"
#include "tlv_tags.h"
#include "es10_display.h"
#include "ipa_display.h"
#include "device_info.h"

/* ERROR */
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#define ERROR_INVALID_DP_ADDRESS                    "invalidDpAddress"
#define ERROR_EUICC_VERSION_NOT_SUPPORTED_BY_DP     "euiccVersionNotSupportedByDp"
#define ERROR_CI_PK_ID_NOT_SUPPORTED                "ciPKIdNotSupported"
#define ERROR_SMDP_ADDRESS_MISMATCH                 "smdpAddressMismatch"
#define ERROR_SMDP_OID_MISMATCH                     "smdpOidMismatch"
#define ERROR_INVALID_EIM_TRANSACTION_ID            "invalidEimTransactionId"
#define ERROR_EUM_CERTIFICATE_INVALID               "eumCertificateInvalid"
#define ERROR_EUM_CERTIFICATE_EXPIRED               "eumCertificateExpired"
#define ERROR_EUICC_CERTIFICATE_INVALID             "euiccCertificateInvalid"
#define ERROR_EUICC_CERTIFICATE_EXPIRED             "euiccCertificateExpired"    
#define ERROR_EUICC_SIGNATURE_INVALID               "euiccSignatureInvalid"
#define ERROR_MATCHING_ID_REFUSED                   "matchingIdRefused"
#define ERROR_EID_MISMATCH                          "eidMismatch"
#define ERROR_NO_ELEGIBLE_PROFILE                   "noEligibleProfile"
#define ERROR_CI_PK_UNKNOWN                         "ciPKUnknown"
#define ERROR_INVALID_TRANSACTION_ID                "invalidTransactionId"
#define ERROR_INSUFFICIENT_MEMORY                   "insufficientMemory"
#define ERROR_PPR_NOT_ALLOWED                       "pprNotAllowed"
#define ERROR_EVENT_ID_UNKNOWN                      "eventIdUnknown"
#define ERROR_CONFIRMATION_CODE_MISSING             "confirmationCodeMissing"
#define ERROR_CONFIRMATION_CODE_REFUSED             "confirmationCodeRefused"
#define ERROR_CONFIRMATION_CODE_RETRIES_EXCEEDED    "confirmationCodeRetriesExceeded"
#define ERROR_BPP_REBINDING_REFUSED                 "bppRebindingRefused"
#define ERROR_DOWNLOAD_ORDER_EXPIRED                "downloadOrderExpired"
#define ERROR_METADATA_MISMATCH                     "metadataMismatch"
#endif // IPA_FEATURE_INDIRECT_DOWNLOAD
#define ERROR_UNDEFINED_ERROR                   "undefinedError"
#define ERROR_UNKNOWN                           "unknown"

/* stateChangeCause */
#define STR_SCC_OTHER_EIM                   "otherEim"
#define STR_SCC_FALLBACK                    "fallback"
#define STR_SCC_EMERGENCY_PROFILE           "emergencyProfile"
#define STR_SCC_LOCAL                       "local"
#define STR_SCC_RESET                       "reset"
#define STR_SCC_IMMEDIATE_ENABLE_PROFILE    "immediateEnableProfile"
#define STR_SCC_DEVICE_CHANGE               "deviceChange"
#define STR_SCC_UNDEFINED                   "undefined"

/* CHOICE */
#define STR_PENDING_NOTIFICATION        "pendingNotification"
#define STR_PROVIDE_EIM_PACKAGE_RESULT  "provideEimPackageResult"
#define STR_EUICC_PACKAGE_REQUEST       "euiccPackageRequest"
#define STR_IPA_EUICC_DATA_REQUEST      "ipaEuiccDataRequest"
#define STR_PROFILE_DOWNLOAD_TRIGGER_REQUEST    "profileDownloadTriggerRequest"
#define STR_EIM_PACKAGE_ERROR           "eimPackageError"
#define STR_EIM_PACKAGE_RESULT_RESPONSE_ERROR   "eimPackageResultResponseError"
#define STR_EUICC_PACKAGE_RESULT        "euiccPackageResult"
#define STR_EPR_AND_NOTIFICATIONS       "ePRAndNotifications"
#define STR_IPA_EUICC_DATA_RESPONSE     "ipaEuiccDataResponse"
#define STR_PROFILE_DOWNLOAD_TRIGGER_RESULT     "profileDownloadTriggerResult"
#define STR_EIM_ACKNOWLEDGEMENTS        "eimAcknowledgements"
#define STR_EIM_PACKAGE_RECEIVED        "eimPackageReceived"
#define STR_EMPTY_RESPONSE              "emptyResponse"
#define STR_PROVIDE_EIM_PACKAGE_RESULT_ERROR    "provideEimPackageResultError"

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD

#define STR_INITITATE_AUTHENTICATION_ERROR_ESIPA(E) \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_DP_ADDRESS ? ERROR_INVALID_DP_ADDRESS : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_EUICC_VERSION_NOT_SUPPORTED_BY_DP ? ERROR_EUICC_VERSION_NOT_SUPPORTED_BY_DP : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED ? ERROR_CI_PK_ID_NOT_SUPPORTED : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_ADDRESS_MISMATCH ? ERROR_SMDP_ADDRESS_MISMATCH : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_OID_MISMATCH ? ERROR_SMDP_OID_MISMATCH : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_EIM_TRANSACTION_ID ? ERROR_INVALID_EIM_TRANSACTION_ID : \
((E) == INITIATE_AUTHENTICATION_ERROR_ESIPA_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN)))))))

#define STR_CANCEL_SESSION_ERROR(E) \
((E) == CANCEL_SESSION_ERROR_ESIPA_INVALID_TRANSACTION_ID ? ERROR_INVALID_TRANSACTION_ID : \
((E) == CANCEL_SESSION_ERROR_ESIPA_EUICC_SIGNATURE_INVALID ? ERROR_EUICC_SIGNATURE_INVALID : \
((E) == CANCEL_SESSION_ERROR_ESIPA_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN)))

#define STR_AUTHENTICATION_CLIENT_ERROR_ESIPA(E) \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_INVALID ? ERROR_EUM_CERTIFICATE_INVALID : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_EXPIRED ? ERROR_EUM_CERTIFICATE_EXPIRED : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_INVALID ? ERROR_EUICC_CERTIFICATE_INVALID : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_EXPIRED ? ERROR_EUICC_CERTIFICATE_EXPIRED : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_SIGNATURE_INVALID ? ERROR_EUICC_SIGNATURE_INVALID : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_MATCHING_ID_REFUSED ? ERROR_MATCHING_ID_REFUSED : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EID_MISMATCH ? ERROR_EID_MISMATCH : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_NO_ELIGIBLE_PROFILE ? ERROR_NO_ELEGIBLE_PROFILE : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_CI_PK_UNKNOWN ? ERROR_CI_PK_UNKNOWN : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_INVALID_TRANSACTION_ID ? ERROR_INVALID_TRANSACTION_ID : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_INSUFFICIENT_MEMORY ? ERROR_INSUFFICIENT_MEMORY : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_PPR_NOT_ALLOWED ? ERROR_PPR_NOT_ALLOWED : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_EVENT_ID_UNKNOWN ? ERROR_EVENT_ID_UNKNOWN : \
((E) == AUTHENTICATE_CLIENT_ERROR_ESIPA_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN))))))))))))))

#define STR_GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA(R)                                                                          \
((R) == GET_BPP_ERROR_ESIPA_EUICC_SIGNATURE_INVALID ? ERROR_EUICC_SIGNATURE_INVALID :                             \
((R) == GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_MISSING ? ERROR_CONFIRMATION_CODE_MISSING :                         \
((R) == GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_REFUSED ? ERROR_CONFIRMATION_CODE_REFUSED :                          \
((R) == GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_RETRIES_EXCEEDED ? ERROR_CONFIRMATION_CODE_RETRIES_EXCEEDED :       \
((R) == GET_BPP_ERROR_ESIPA_BPP_REBINDING_REFUSED ? ERROR_BPP_REBINDING_REFUSED :                                 \
((R) == GET_BPP_ERROR_ESIPA_DOWNLOAD_ORDER_EXPIRED ? ERROR_DOWNLOAD_ORDER_EXPIRED :                               \
((R) == GET_BPP_ERROR_ESIPA_METADATA_MISMATCH ? ERROR_METADATA_MISMATCH :                         \
((R) == GET_BPP_ERROR_ESIPA_INVALID_TRANSACTION_ID ? ERROR_INVALID_TRANSACTION_ID :                               \
((R) == GET_BPP_ERROR_ESIPA_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                                             \
ERROR_UNKNOWN)))))))))
#endif

#define STR_HANDLE_NOTIFICATION_ESIPA_CHOICE(E) \
((E) == PENDING_NOTIFICATION_CHOICE_HNE ? STR_PENDING_NOTIFICATION : \
((E) == PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE ? STR_PROVIDE_EIM_PACKAGE_RESULT : \
ERROR_UNKNOWN))

#define STR_GET_EIM_PACKAGE_RESPONSE_CHOICE(E) \
((E) == EUICC_PACKAGE_REQUEST_CHOICE_GEPR ? STR_EUICC_PACKAGE_REQUEST : \
((E) == IPA_EUICC_DATA_REQUEST_CHOICE_GEPR ? STR_IPA_EUICC_DATA_REQUEST : \
((E) == PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR ? STR_PROFILE_DOWNLOAD_TRIGGER_REQUEST : \
((E) == EIM_PACKAGE_ERROR_CHOICE_GEPR ? STR_EIM_PACKAGE_ERROR : \
ERROR_UNKNOWN))))

#define STR_PROVIDE_EIM_PACKAGE_RESULT_CHOICE(E) \
((E) == EUICC_PACKAGE_RESULT_CHOICE_PEPR ? STR_EUICC_PACKAGE_RESULT : \
((E) == EPR_AND_NOTIFICATIONS_CHOICE_PEPR ? STR_EPR_AND_NOTIFICATIONS : \
((E) == IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR ? STR_IPA_EUICC_DATA_RESPONSE : \
((E) == PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR ? STR_PROFILE_DOWNLOAD_TRIGGER_RESULT : \
((E) == EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR ? STR_EIM_PACKAGE_RESULT_RESPONSE_ERROR : \
ERROR_UNKNOWN)))))

#define STR_PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE(E) \
((E) == EIM_ACKNOWLEDGEMENTS_CHOICE_PEPRR ? STR_EIM_ACKNOWLEDGEMENTS : \
((E) == EMPTY_RESPONSE_CHOICE_PEPRR ? STR_EMPTY_RESPONSE : \
((E) == PROVIDE_EIM_PACKAGE_RESULT_ERROR_CHOICE_PEPRR ? STR_PROVIDE_EIM_PACKAGE_RESULT_ERROR : \
ERROR_UNKNOWN)))

#define STR_TRANSFER_EIM_PACKAGE_REQUEST_CHOICE(E) \
((E) == EUICC_PACKAGE_REQUEST_CHOICE_TEPR ? STR_EUICC_PACKAGE_REQUEST : \
((E) == IPA_EUICC_DATA_REQUEST_CHOICE_TEPR ? STR_IPA_EUICC_DATA_REQUEST : \
((E) == EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR ? STR_EIM_ACKNOWLEDGEMENTS : \
((E) == PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR ? STR_PROFILE_DOWNLOAD_TRIGGER_REQUEST : \
ERROR_UNKNOWN))))

#define STR_TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE(E) \
((E) == EUICC_PACKAGE_RESULT_CHOICE_TEPR ? STR_EUICC_PACKAGE_RESULT : \
((E) == EPR_AND_NOTIFICATIONS_CHOICE_TEPR ? STR_EPR_AND_NOTIFICATIONS : \
((E) == IPA_EUICC_DATA_RESPONSE_CHOICE_TEPR ? STR_IPA_EUICC_DATA_RESPONSE : \
((E) == EIM_PACKAGE_RECEIVED_CHOICE_TEPR ? STR_EIM_PACKAGE_RECEIVED : \
((E) == EIM_PACKAGE_ERROR_CHOICE_TEPR ? STR_EIM_PACKAGE_ERROR : \
ERROR_UNKNOWN)))))

#define STR_STATE_CHANGE_CAUSE(C) \
((C) == STATE_CHANGE_CAUSE_OTHER_EIM ? STR_SCC_OTHER_EIM : \
((C) == STATE_CHANGE_CAUSE_FALLBACK ? STR_SCC_FALLBACK : \
((C) == STATE_CHANGE_CAUSE_EMERGENCY_PROFILE ? STR_SCC_EMERGENCY_PROFILE : \
((C) == STATE_CHANGE_CAUSE_LOCAL ? STR_SCC_LOCAL : \
((C) == STATE_CHANGE_CAUSE_RESET ? STR_SCC_RESET : \
((C) == STATE_CHANGE_CAUSE_IMMEDIATE_ENABLE_PROFILE ? STR_SCC_IMMEDIATE_ENABLE_PROFILE : \
((C) == STATE_CHANGE_CAUSE_DEVICE_CHANGE ? STR_SCC_DEVICE_CHANGE : \
((C) == STATE_CHANGE_CAUSE_UNDEFINED ? STR_SCC_UNDEFINED : \
ERROR_UNKNOWN))))))))

static void esipa_display__transaction_id(const char* header, const char* tail, const transaction_id_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
void esipa_display__initiate_authentication_request_esipa(const initiate_authentication_request_esipa_t* obj) {
#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
    LOGI("InitiateAuthenticationRequestEsipa(euiccChallenge=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X, smdpAddress=%s)", 
    obj->euicc_challenge.challenge[0], obj->euicc_challenge.challenge[1], obj->euicc_challenge.challenge[2], obj->euicc_challenge.challenge[3], 
    obj->euicc_challenge.challenge[4], obj->euicc_challenge.challenge[5], obj->euicc_challenge.challenge[6], obj->euicc_challenge.challenge[7], 
    obj->euicc_challenge.challenge[8], obj->euicc_challenge.challenge[9], obj->euicc_challenge.challenge[10], obj->euicc_challenge.challenge[11], 
    obj->euicc_challenge.challenge[12], obj->euicc_challenge.challenge[13], obj->euicc_challenge.challenge[14], obj->euicc_challenge.challenge[15],
    obj->smdp_address.fqdn);
#else
    LOGI("InitiateAuthenticationRequestEsipa(euiccChallenge=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X)", 
    obj->euicc_challenge.challenge[0], obj->euicc_challenge.challenge[1], obj->euicc_challenge.challenge[2], obj->euicc_challenge.challenge[3], 
    obj->euicc_challenge.challenge[4], obj->euicc_challenge.challenge[5], obj->euicc_challenge.challenge[6], obj->euicc_challenge.challenge[7], 
    obj->euicc_challenge.challenge[8], obj->euicc_challenge.challenge[9], obj->euicc_challenge.challenge[10], obj->euicc_challenge.challenge[11], 
    obj->euicc_challenge.challenge[12], obj->euicc_challenge.challenge[13], obj->euicc_challenge.challenge[14], obj->euicc_challenge.challenge[15]);
#endif
}

void esipa_display__initiate_authentication_response_esipa(const initiate_authentication_response_esipa_t* obj) {
    LOGI("InitiateAuthenticationResponseEsipa");
    switch (obj->choice)
    {
    case INITIATE_AUTHENTICATION_OK_ESIPA_CHOICE:
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
        if (obj->value.initiate_authentication_ok_esipa.field_is_present.transaction_id) {
            esipa_display__transaction_id("\tinitiateAuthenticationOkEsipa(", ")", &obj->value.initiate_authentication_ok_esipa.transaction_id);
        } else {
#endif
            LOGI("\tinitiateAuthenticationOkEsipa");
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
        }
#endif
        break;
    case INITIATE_AUTHENTICATION_ERROR_ESIPA_CHOICE:
        LOGI("\tinitiateAuthenticationErrorEsipa(%s)", STR_INITITATE_AUTHENTICATION_ERROR_ESIPA(obj->value.initiate_authentication_error_esipa));
        break;
    default:
        LOGE("[esipa_display__initiate_authentication_response_esipa] Unknown choice %d", obj->choice);
        break;
    }
}

void esipa_display__authenticate_client_request_esipa(const authenticate_client_request_esipa_t* obj) {
    esipa_display__transaction_id("AuthenticateClientRequestEsipa(", ")", &obj->transaction_id);
}

void esipa_display__authenticate_client_response_esipa(const authenticate_client_response_esipa_t* obj) {
    LOGI("AuthenticateClientResponseEsipa");
    switch (obj->choice) {
    case AUTHENTICATE_CLIENT_OK_DP_ESIPA_CHOICE:
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
        if (obj->value.authenticate_client_ok_dp_esipa.field_is_present.transaction_id) {
            esipa_display__transaction_id("\tauthenticateClientOkDPEsipa(", ")", &obj->value.authenticate_client_ok_dp_esipa.transaction_id);
        } else {
#endif
            LOGI("\tauthenticateClientOkDPEsipa");
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
        }
#endif
        break;
    case AUTHENTICATE_CLIENT_OK_DS_ESIPA_CHOICE:
        esipa_display__transaction_id("\tauthenticateClientOkDSEsipa(", obj->value.authenticate_client_ok_ds_esipa.field_is_present.profile_download_trigger ? ", profileDownloadTrigger)" : ")", &obj->value.authenticate_client_ok_ds_esipa.transaction_id);
        break;
    case AUTHENTICATE_CLIENT_ERROR_ESIPA_CHOICE:
        LOGI("\tauthenticateClientErrorEsipa(%s)", STR_AUTHENTICATION_CLIENT_ERROR_ESIPA(obj->value.authenticate_client_error_esipa));
        break;
    default:
        LOGE("[esipa_display__authenticate_client_response_esipa] Unknown choice %d", obj->choice);
        break;
    }
}

void esipa_display__get_bound_profile_package_request_esipa(const get_bound_profile_package_request_esipa_t* obj) {
    esipa_display__transaction_id("GetBoundProfilePackageRequestEsipa(", ")", &obj->transaction_id);
}

void esipa_display__get_bound_profile_package_response_esipa(const get_bound_profile_package_response_esipa_t* obj) {
    switch (obj->choice) { 
        case GET_BOUND_PROFILE_PACKAGE_OK_ESIPA_CHOICE:
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
            LOGI("\tgetBoundProfilePackageOkEsipa");
#else
            esipa_display__transaction_id("\tgetBoundProfilePackageOkEsipa(", ")", &obj->value.get_bound_profile_package_ok_esipa.transaction_id);
#endif
            break;
        case GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA_CHOICE:
            LOGI("\tgetBoundProfilePackageErrorEsipa(%s)", STR_GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA(obj->value.get_bound_profile_package_error_esipa));
            break;
        default:
            LOGE("[esipa_display__get_bound_profile_package_response_esipa] Unknown choice %d", obj->choice);
            break;
        }
    }
    
void esipa_display__cancel_session_request_esipa(const cancel_session_request_esipa_t* obj) {
    esipa_display__transaction_id("CancelSessionRequestEsipa(", ")", &obj->transaction_id);
}

void esipa_display__cancel_session_response_esipa(const cancel_session_response_esipa_t* obj) {
    LOGI("CancelSessionResponseEsipa");
    switch (obj->choice)
    {
    case CANCEL_SESSION_OK_ESIPA:
        LOGI("\tcancelSessionOk");
        break;
    case CANCEL_SESSION_ERROR_ESIPA:
        LOGI("\tcancelSessionError(%s)", STR_CANCEL_SESSION_ERROR(obj->cancel_session_error));
        break;
    default:
        LOGE("[esipa_display__cancel_session_response_esipa] Unknown choice %d", obj->choice);
        break;
    }
}
#endif
void esipa_display__handle_notification_esipa(const handle_notification_esipa_t* obj) {
    LOGI("HandleNotificationEsipa(%s)", STR_HANDLE_NOTIFICATION_ESIPA_CHOICE(obj->choice));
}

void esipa_display__get_eim_package_request(const get_eim_package_request_t* obj) {
    LOGI("GetEimPackageRequest");
    LOGI("  eidValue=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
    obj->eid.eid[0], obj->eid.eid[1], obj->eid.eid[2], obj->eid.eid[3], obj->eid.eid[4], obj->eid.eid[5], obj->eid.eid[6], obj->eid.eid[7], 
    obj->eid.eid[8], obj->eid.eid[9], obj->eid.eid[10], obj->eid.eid[11], obj->eid.eid[12], obj->eid.eid[13], obj->eid.eid[14], obj->eid.eid[15]);
    if (obj->field_is_present.notify_state_change) {
        LOGI("  notifyStateChange");
        LOGI("  stateChangeCause=%s", STR_STATE_CHANGE_CAUSE(obj->state_change_cause));
    }
    if (obj->field_is_present.rplmn) {
        LOGI("  rPLMN=%02X%02X%02X", obj->rplmn.value[0], obj->rplmn.value[1], obj->rplmn.value[2]);
    }
}

void esipa_display__get_eim_package_response(const get_eim_package_response_t* obj) {
    LOGI("GetEimPackageResponse(%s)", STR_GET_EIM_PACKAGE_RESPONSE_CHOICE(obj->choice));
}

void esipa_display__provide_eim_package_result(const provide_eim_package_result_t* obj) {
    if (obj->field_is_present.eid_value) {
        LOGI("ProvideEimPackageResult(eidValue=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X, eimPackageResult=%s)",
        obj->eid_value.eid[0], obj->eid_value.eid[1], obj->eid_value.eid[2], obj->eid_value.eid[3], obj->eid_value.eid[4], obj->eid_value.eid[5], obj->eid_value.eid[6], obj->eid_value.eid[7], 
        obj->eid_value.eid[8], obj->eid_value.eid[9], obj->eid_value.eid[10], obj->eid_value.eid[11], obj->eid_value.eid[12], obj->eid_value.eid[13], obj->eid_value.eid[14], obj->eid_value.eid[15],
        STR_PROVIDE_EIM_PACKAGE_RESULT_CHOICE(obj->eim_package_result.choice));
    } else {
        LOGI("ProvideEimPackageResult(eimPackageResult=%s)", STR_PROVIDE_EIM_PACKAGE_RESULT_CHOICE(obj->eim_package_result.choice));
    }
}

void esipa_display__provide_eim_package_result_response(const provide_eim_package_result_response_t* obj) {
    LOGI("ProvideEimPackageResultResponse(%s)", STR_PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE(obj->choice));
}

void esipa_display__transfer_eim_package_request(const transfer_eim_package_request_t* obj) {
    LOGI("TransferEimPackageRequest(%s)", STR_TRANSFER_EIM_PACKAGE_REQUEST_CHOICE(obj->choice));
}

void esipa_display__transfer_eim_package_response(const transfer_eim_package_response_t* obj) {
    LOGI("TransferEimPackageResponse(%s)", STR_TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE(obj->choice));
}

static void esipa_display__transaction_id(const char* header, const char* tail, const transaction_id_t* obj) {
    int err;
    char transaction_id[sizeof(obj->transaction_id) * 2 + 1];

    err = sprintf(transaction_id, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", 
    obj->transaction_id[0], obj->transaction_id[1], obj->transaction_id[2], obj->transaction_id[3],
    obj->transaction_id[4], obj->transaction_id[5], obj->transaction_id[6], obj->transaction_id[7],
    obj->transaction_id[8], obj->transaction_id[9], obj->transaction_id[10], obj->transaction_id[11],
    obj->transaction_id[12], obj->transaction_id[13], obj->transaction_id[14], obj->transaction_id[15]);
    
    if (err < 0) {
        LOGW("[esipa_display__transaction_id] Error printing the transactionId, err %d", err);
        return;
    }

    transaction_id[obj->transaction_id_size * 2] = '\0';
    LOGI("%stransactionId=%s%s", header, transaction_id, tail);
}
