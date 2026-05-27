/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa.h"
#include "esipa_data_binding.h"
#include "esipa_tlv_extractor.h"
#include "esipa_display.h"
#include "timer.h"
#include "ipa.h"
#include "log.h"

static ErrCode esipa__get_transaction_id(const get_eim_package_response_t* request, bool* transaction_id_found, transaction_id_t* obj);
static bool esipa__eim_transaction_id_is_present(const eim_package_result_t* in);
static bool esipa__ipa_euicc_data_response_eim_transaction_id_is_present(const ipa_euicc_data_response_t* in);
static bool esipa__euicc_package_result_eim_transaction_id_is_present(const euicc_package_result_t* in);
/* purely-virtual functions should never be called */
static ErrCode esipa__init_default(esipa_t* const me);

void esipa__ctor(esipa_t * const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, int port, gsma_data_binding_t data_binding, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size) {
    static struct esipa_vtbl_s const vtbl = {
        &esipa__init_default
    };
    me->vptr = &vtbl;

    me->eim_id = eim_id;
    me->eim_id_size = eim_id_size;
    me->fqdn = fqdn;
    me->port = port;
    me->data_binding = data_binding;
    me->trusted_certificate_tls = trusted_certificate_tls;
    me->trusted_certificate_tls_size = trusted_certificate_tls_size;
    me->last_transmission.tv_sec = 0;
    me->last_transmission.tv_nsec = 0;
    me->last_message_sent = GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI; // Will be the first message to send
}

void esipa__destroy(esipa_t * const me) {
    memset(me, 0, sizeof(esipa_t));
    me->data_binding = UNDEFINED_DATA_BINDING;
}

ErrCode esipa__init(esipa_t* const me) {
    /* Virtual Call (Late Binding) */
    return(*me->vptr->esipa_init)(me);
}

ErrCode esipa__update_last_transmission(esipa_t* const me) {
    int err;

    if (!me) {
        LOGE("[esipa__update_last_transmission] The ESipa instance is null");
        return eBadArg;
    }

    if ((err = timer__get_clock_data(&me->last_transmission)) < 0) {
        LOGE("[esipa__update_last_transmission] Error on update the last transmission, err %d", err);
        return eFatal;
    }

    return eOk;
}

ErrCode esipa__get_last_transmission(esipa_t* const me, clock_data_t* last_transmission) {
    /* Check input parameters */
    if (!me) {
        LOGE("[esipa__get_last_transmission] The ESipa instance is null");
        return eBadArg;
    }
    if (!last_transmission) {
        LOGE("[esipa__get_last_transmission] The last transmission pointer is null");
        return eBadArg;
    }

    /* Copy the last transmission clock */
    memcpy(last_transmission, &me->last_transmission, sizeof(clock_data_t));
    return eOk;
}

gsma_data_binding_t esipa__get_data_binding(esipa_t* const me) {
    if (!me) {
        LOGE("[esipa__get_data_binding] The ESipa instance is null");
        return UNDEFINED_DATA_BINDING;
    }

    return me->data_binding;
}

const char* esipa__get_fqdn(esipa_t* const me) {
    if (me) {
        return me->fqdn;
    } else {
        return NULL;
    }
}

void esipa__set_last_message_sent(esipa_t* const me, esipa_message_from_ipa_to_eim_choice_t last_message_sent) {
    if (me) {
        me->last_message_sent = last_message_sent;
        LOGT("[esipa__set_last_message_sent] Last message sent: %d", last_message_sent);
    }
}

esipa_message_from_ipa_to_eim_choice_t esipa__get_last_message_sent(esipa_t* const me) {
    if (me) {
        return me->last_message_sent;
    } else {
        return GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI;
    }
}

ErrCode esipa__get_eim_package_request(esipa_t* const me, get_eim_package_request_t* out) {
    /* Check input parameters */
    if (!me) {
        LOGE("[esipa__get_eim_package_request] The ESipa instance is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa__get_eim_package_request] The GetEimPackageRequest object is null");
        return eBadArg;
    }

    /* Set the EID */
    ipa__get_eid(&out->eid);

    /* Set the notifyStateChange and stateChangeCause */
    out->field_is_present.notify_state_change = ipa__get_notify_state_change(&out->state_change_cause); // TODO: Filter by eimId

    /* Set the rPLMN */
    if (ipa__get_mcc_mnc(&out->rplmn) != eOk) {
        out->field_is_present.rplmn = false;
    }  else {
        out->field_is_present.rplmn = true;
    }

    return eOk;
}

ErrCode esipa__execute_provide_eim_package_result_response(provide_eim_package_result_response_t* in) {
    ErrCode rc;

    /* Check input parameters */
    if (!in) {
        LOGE("[esipa__execute_provide_eim_package_result_response] The ProvideEimPackageResultResponse object is null");
        return eBadArg;
    }

    /* Execute the use case in the IPA */
    switch (in->choice)
    {
    case EIM_ACKNOWLEDGEMENTS_CHOICE_PEPRR:
        if ((rc = ipa__eim_acknowledgements(&in->value.eim_acknowledgements)) != eOk) {
            LOGE("[esipa__execute_provide_eim_package_result_response] Error executing the Eim Acknowledgements on the IPA, rc %d", rc);
            return rc;
        }
        return eOk;
    case EMPTY_RESPONSE_CHOICE_PEPRR:
        LOGD("[esipa__execute_provide_eim_package_result_response] The ProvideEimPackageResultResponse CHOICE is emptyResponse");
        return eOk;
    case PROVIDE_EIM_PACKAGE_RESULT_ERROR_CHOICE_PEPRR:
        LOGW("[esipa__execute_provide_eim_package_result_response] provideEimPackageResultError(%d)", in->value.provide_eim_package_result_error);
        return eFatal;
    default:
        LOGE("[ipa__profile_download_trigger] Unknown ProvideEimPackageResultResponse CHOICE %d", in->choice);
        return eBadArg;
    }
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
ErrCode esipa__execute_cancel_session_response_esipa(esipa_t* const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    cancel_session_response_esipa_t request = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding(me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_cancel_session_response_esipa(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa__execute_cancel_session_response_esipa] Error parsing CancelSessionResponseEsipa message, rc %d", rc);
        return rc;
    }

    esipa_display__cancel_session_response_esipa(&request);
    return eOk;    
}
#endif

ErrCode esipa__set_eim_package_result_response_error(const get_eim_package_response_t* request, const eim_package_error_from_ipa_to_eim_t error, eim_package_result_t* out) {
    ErrCode rc;
    
    if (!out) {
        LOGE("[esipa__set_eim_package_result_response_error] ProvideEimPackageResult object is null");
        return eBadArg;
    }

    out->choice = EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR; // Set the CHOICE
    out->value.eim_package_result_response_error.eim_package_result_error_code = error; // Set the eimPackageResultErrorCode
    /* Set the transactionId (if any) */
    rc = esipa__get_transaction_id(request, &out->value.eim_package_result_response_error.field_is_present.eim_transaction_id, &out->value.eim_package_result_response_error.eim_transaction_id);
    if (rc != eOk) {
        out->value.eim_package_result_response_error.field_is_present.eim_transaction_id = false;
    }

    return eOk;
}

ErrCode esipa__set_provide_eim_package_result_eid_value(provide_eim_package_result_t* obj) {
    if (!obj) {
        LOGE("[esipa__set_provide_eim_package_result_eid] The ProvideEimPackageResult object is null");
        return eBadArg;
    }

    /* Set the EID */
    if (esipa__eim_transaction_id_is_present(&obj->eim_package_result)) {
        // If the ProvideEimPackageResult has transactionId, the eIM doesn't need the EID to track the response
        LOGD("[esipa__set_provide_eim_package_result_eid] The eimTransactionId is present in the EimPackageResult. The eidValue is not included in the ProvideEimPackageResult.");
        obj->field_is_present.eid_value = false;
    } else {
        // If the ProvideEimPackageResult does not have transactionId, the eIM need the EID to track the response
        LOGD("[esipa__set_provide_eim_package_result_eid] The eimTransactionId is not present in the EimPackageResult. The eidValue is included in the ProvideEimPackageResult.");
        obj->field_is_present.eid_value = true;
        ipa__get_eid(&obj->eid_value);
    }

    return eOk;
}

static ErrCode esipa__get_transaction_id(const get_eim_package_response_t* request, bool* transaction_id_found, transaction_id_t* obj) {
    ErrCode rc;
    euicc_package_request_t euicc_package_request = { 0 };
    const transaction_id_t* transaction_id = NULL;
    
    if (!request) {
        LOGE("[esipa__get_transaction_id] GetEimPackageResponse object is null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[esipa__get_transaction_id] TransactionId object is null");
        return eBadArg;
    }
    if (!transaction_id_found) {
        LOGE("[esipa__get_transaction_id] The TransactionId is found boolean pointer is null");
        return eBadArg;
    }

    // Initialize the response
    *transaction_id_found = false;
    memset(obj, 0, sizeof(transaction_id_t));

    // Find the transactionId
    switch (request->choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_GEPR:
        if ((rc = esipa_tlv_extractor__euicc_package_request(request->value.euicc_package_request.euicc_package_request, request->value.euicc_package_request.euicc_package_request_size, &euicc_package_request)) != eOk) {
            LOGE("[esipa__get_transaction_id] Error parsing the EuiccPackageRequest, rc %d", rc);
            return rc;
        }
        if (euicc_package_request.euicc_package_signed.field_is_present.eim_transaction_id) {
            LOGD("[esipa__get_transaction_id] TransactionId found in the EuiccPackageRequest");
            transaction_id = &euicc_package_request.euicc_package_signed.eim_transaction_id;
        } else {
            LOGD("[esipa__get_transaction_id] TransactionId not found in the EuiccPackageRequest");
        }
        break;
    case IPA_EUICC_DATA_REQUEST_CHOICE_GEPR:
        if (request->value.ipa_euicc_data_request.field_is_present.eim_transaction_id) {
            LOGD("[esipa__get_transaction_id] TransactionId found in the IpaEuiccDataRequest");
            transaction_id = &request->value.ipa_euicc_data_request.eim_transaction_id;
        } else {
            LOGD("[esipa__get_transaction_id] TransactionId not found in the IpaEuiccDataRequest");
        }
        break;
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR:
        if (request->value.profile_download_trigger_request.field_is_present.eim_transaction_id) {
            LOGD("[esipa__get_transaction_id] TransactionId found in the ProfileDownloadTriggerRequest");
            transaction_id = &request->value.profile_download_trigger_request.eim_transaction_id;
        } else {
            LOGD("[esipa__get_transaction_id] TransactionId not found in the ProfileDownloadTriggerRequest");
        }
        break;
    case EIM_PACKAGE_ERROR_CHOICE_GEPR:
        LOGD("[esipa__get_transaction_id] The GetEimPackageResponse is a eimPackageError, the TransactionId can not be found");
        break;
    default:
        LOGE("[esipa__get_transaction_id] Unknown GetEimPackageResponse CHOICE %d", request->choice);
        return eFatal;
    }

    // Set the response
    if (transaction_id) {
        *transaction_id_found = true;
        memcpy(obj, transaction_id, sizeof(transaction_id_t));
        LOG_DATA(eLogDebug, "[esipa__get_transaction_id] TransactionId", obj->transaction_id, obj->transaction_id_size);
    } else {
        *transaction_id_found = false;
        LOGD("[esipa__get_transaction_id] TransactionId not found");
    }
    
    return eOk;
}

static bool esipa__eim_transaction_id_is_present(const eim_package_result_t* in) {
    if (!in) {
        LOGW("[esipa__eim_transaction_id_is_present] EimPackageResult object is null. Assuming eimTransactionId is not present.");
        return false;
    }

    // Find the transactionId
    switch (in->choice)
    {
    case EUICC_PACKAGE_RESULT_CHOICE_PEPR:
        return esipa__euicc_package_result_eim_transaction_id_is_present(&in->value.euicc_package_result.obj);
    case EPR_AND_NOTIFICATIONS_CHOICE_PEPR:
        return esipa__euicc_package_result_eim_transaction_id_is_present(&in->value.epr_and_notifications.euicc_package_result.obj);
    case IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR:
        return esipa__ipa_euicc_data_response_eim_transaction_id_is_present(&in->value.ipa_euicc_data_response);
    case PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR:
        return in->value.profile_download_trigger_result.field_is_present.eim_transaction_id;
    case EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR:
        return in->value.eim_package_result_response_error.field_is_present.eim_transaction_id;
    default:
        LOGW("[esipa__eim_transaction_id_is_present] Unknown EimPackageResult CHOICE %d. Assuming eimTransactionId is not present.", in->choice);
        return false;
    }
}

static bool esipa__ipa_euicc_data_response_eim_transaction_id_is_present(const ipa_euicc_data_response_t* in) {
    if (!in) {
        LOGW("[esipa__ipa_euicc_data_response_eim_transaction_id_is_present] IpaEuiccDataResponse object is null. Assuming eimTransactionId is not present.");
        return false;
    }

    // Find the transactionId
    switch (in->choice)
    {
    case IPA_EUICC_DATA_CHOICE:
        return in->value.ipa_euicc_data.field_is_present.eim_transaction_id;
    case IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE:
        return in->value.ipa_euicc_data_response_error.field_is_present.eim_transaction_id;
    default:
        LOGW("[esipa__ipa_euicc_data_response_eim_transaction_id_is_present] Unknown IpaEuiccData CHOICE %d. Assuming eimTransactionId is not present.", in->choice);
        return false;
    }
}

static bool esipa__euicc_package_result_eim_transaction_id_is_present(const euicc_package_result_t* in) {
    if (!in) {
        LOGW("[esipa__euicc_package_result_eim_transaction_id_is_present] EuiccPackageResult object is null. Assuming eimTransactionId is not present.");
        return false;
    }

    // Find the transactionId
    switch (in->choice)
    {
    case EUICC_PACKAGE_RESULT_SIGNED_CHOICE:
        return in->value.euicc_package_result_signed.euicc_package_result_data_signed.field_is_present.eim_transaction_id;
    case EUICC_PACKAGE_ERROR_SIGNED_CHOICE:
        return in->value.euicc_package_error_signed.euicc_package_error_data_signed.field_is_present.eim_transaction_id;
    case EUICC_PACKAGE_ERROR_UNSIGNED_CHOICE:
        return in->value.euicc_package_error_unsigned.field_is_present.eim_transaction_id;
    default:
        LOGW("[esipa__euicc_package_result_eim_transaction_id_is_present] Unknown EuiccPackageResult CHOICE %d. Assuming eimTransactionId is not present.", in->choice);
        return false;
    }
}

static ErrCode esipa__init_default(esipa_t* const me) {
    return eNotImpl; /* purely-virtual function should never be called */
}
