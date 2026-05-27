/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#if defined(ENABLE_HTTP_ESIPA)
#include "esipa_sync.h"
#include "esipa_data_binding.h"
#include "esipa_display.h"
#include "ipa.h"
#include "timer.h"
#include "log.h"
#include "ipa_core.h"
#include "memory_manager.h"
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#include "esipa_message_from_ipa_to_eim_typedefs.h"
#include "esipa_message_from_eim_to_ipa_typedefs.h"
#endif
#define ESIPA_SYNC_SLEEP 60

/* Subclass implementation of the parent virtual functions */
static ErrCode esipa_sync__init(esipa_t* const me);

static ErrCode esipa_sync__execute_eim_package_retrieval(esipa_sync_t * const me);
static ErrCode esipa_sync__execute_get_eim_package_response(esipa_sync_t * const me, get_eim_package_response_t* req);

/* Functions to process the requests */
static ErrCode esipa_sync__execute_euicc_package_request(esipa_sync_t * const me, get_eim_package_response_t* req);
static ErrCode esipa_sync__execute_ipa_euicc_data_request(esipa_sync_t * const me, get_eim_package_response_t* req);
static ErrCode esipa_sync__execute_profile_download_trigger_request(esipa_sync_t * const me, get_eim_package_response_t* req);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_sync__send_initiate_authentication_request_esipa(esipa_sync_t* const me, const initiate_authentication_request_esipa_t* in, initiate_authentication_response_esipa_t* out);
static ErrCode esipa_sync__send_authenticate_client_request_esipa(esipa_sync_t* const me, const authenticate_client_request_esipa_t* in, authenticate_client_response_esipa_t* out);
static ErrCode esipa_sync__send_get_bound_profile_package_request_esipa(esipa_sync_t* const me, const get_bound_profile_package_request_esipa_t* in, get_bound_profile_package_response_esipa_t* out);
static ErrCode esipa_sync__send_cancel_session_request_esipa(esipa_sync_t* const me, const cancel_session_request_esipa_t* in, cancel_session_response_esipa_t* out);
static ErrCode esipa_sync__execute_indirect_download(esipa_sync_t* const me, const initiate_authentication_request_esipa_t* in);
static ErrCode esipa_sync__execute_indirect_profile_download_trigger_request(esipa_sync_t* const me, const profile_download_trigger_request_t* req);
#endif

/* Functions to send and process responses */
static ErrCode esipa_sync__execute_eim_package_result(esipa_sync_t * const me, provide_eim_package_result_t* req);
static ErrCode esipa_sync__execute_eim_package_result_on_error(esipa_sync_t * const me, const get_eim_package_response_t* req, const eim_package_error_from_ipa_to_eim_t error, provide_eim_package_result_t* in);

/* Functions to send EsipaMessageFromIpaToEim */
static ErrCode esipa_sync__send_get_eim_package_request(esipa_sync_t * const me, get_eim_package_response_t* out);
static ErrCode esipa_sync__send_handle_notification_esipa(esipa_sync_t * const me, const handle_notification_esipa_t* in);
static ErrCode esipa_sync__send_provide_eim_package_result(esipa_sync_t * const me, const provide_eim_package_result_t* in, provide_eim_package_result_response_t* out);

/* Functions to free allocations done in this file */
static void esipa_sync__free_get_eim_package_response(get_eim_package_response_t* obj);
static void esipa_sync__free_provide_eim_package_result_response(provide_eim_package_result_response_t* obj);

/* Virtual Call (Late Binding) */
static ErrCode esipa_sync__send_message(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size);

/* purely-virtual functions should never be called */
static ErrCode esipa_sync__send_message_default(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size);

void esipa_sync__ctor(esipa_sync_t * const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size, uint32_t max_time_without_transmission, gsma_data_binding_t data_binding, uint32_t sync_sleep_time) {
    static struct esipa_vtbl_s const esipa_vtbl = {  /* vtbl of the ESipa class */
        &esipa_sync__init
    };
    esipa__ctor(&me->super, eim_id, eim_id_size, fqdn, 0, data_binding, trusted_certificate_tls, trusted_certificate_tls_size); /* call the superclass constructor */
    me->super.vptr = &esipa_vtbl; /* override the vptr */
    
    /* Set attributes of the class */
    static struct esipa_sync_vtbl_s const vtbl = {
        &esipa_sync__send_message_default
    };
    me->vptr = &vtbl; // The ESipa Sync subclass shall overwrite this virtual table

    me->max_time_without_transmission = max_time_without_transmission;
    me->sync_sleep_time = sync_sleep_time;
    LOGD("[esipa_sync__ctor] Max time without transmission: %us", me->max_time_without_transmission);
}

void esipa_sync__destroy(esipa_sync_t * const me) {
    if (me) {
        /* Reset the attributes of the subclass */
        me->max_time_without_transmission = 0;

        /* Destroy the parent instance */
        esipa__destroy((esipa_t*) me);
    }
}

static ErrCode esipa_sync__init(esipa_t* const me) {
    ErrCode rc;
    clock_data_t current_clock;
    clock_data_t last_transmission_clock;
    esipa_sync_t* const me_ = (esipa_sync_t*) me; /* explicit downcast */
    uint32_t task_id = 0;
    if (!me) {
        LOGE("[esipa_sync__init] The ESipa Sync instance is null");
        return eBadArg;
    }

    notify_app(IPA_EVENT_SERVICE_START_SUCCESS, NULL);

    while (!ipa__get_ipa_exit()) {
        /* Get clocks to calculate the time elapsed between now and the last transmission */
        if (timer__get_clock_data(&current_clock) < 0) {
            LOGW("[esipa_sync__init] Error on retrieve he current clock");
            continue; // Try to get the current clock in the next iteration
        }

        if ((rc = esipa__get_last_transmission((esipa_t*) me, &last_transmission_clock)) != eOk) {
            LOGW("[esipa_sync__init] Error on retrieve he last transmission clock");
            continue; // Try to get the last transmission clock in the next iteration
        }

        /** Check if we need to trigger a eIM Package Retrieval Procedure. TODO: Check the NotifyStateChange filtering by eimId */
        if (ipa__is_available() && (ipa__get_notify_state_change(NULL) || (current_clock.tv_sec - last_transmission_clock.tv_sec) >= (int64_t) me_->max_time_without_transmission)) {
            LOGD("[esipa_sync__init] The eIM Package Retrieval Procedure will be executed");
            notify_task_start(task_id);
            if ((rc = esipa_sync__execute_eim_package_retrieval(me_)) != eOk) {
                LOGW("[esipa_sync__init] Failed execute the eIM Package Retrieval Procedure, rc %d. Another attempt will be triggered later.", rc);
            }
        }

        notify_task_end(task_id++);
        /* Sleep before the next iteration */
        LOGD("[esipa_sync__init] ESipa sync thread sleeping for %ds", me_->sync_sleep_time);
        if (me_->sync_sleep_time == 0) {
            timer__sleep(0);
        } else {
            uint32_t elapsed = 0;
            while (!ipa__get_ipa_exit() && elapsed < me_->sync_sleep_time) {
                timer__sleep(1);
                elapsed++;
            }
        }
    }
    return eOk;
}

/* IPA to eIM */
static ErrCode esipa_sync__execute_eim_package_retrieval(esipa_sync_t * const me) {
    ErrCode rc;
    get_eim_package_response_t get_eim_package_response = { 0 };
    bool eim_package_available = true;

    /* Check if the IPA is available to start the eIM Package Retrieval Procedure */
    if (ipa__take() != 0) { // Since it is a synchronous protocol, we can take the IPA until the end of the eIM Package Retrieval Procedure
        LOGW("[esipa_sync__execute_eim_package_retrieval] The IPA is not available to start the eIM Package Retrieval Procedure. The start of the procedure will be postponed until the IPA is available again.");
        return eFatal;
    }

    while (eim_package_available) {
        /* Send a GetEimPackageRequest */
        if ((rc = esipa_sync__send_get_eim_package_request(me, &get_eim_package_response)) != eOk) {
            LOGE("[esipa_sync__execute_eim_package_retrieval] Error on send the GetEimPackageRequest, rc %d", rc);
            ipa__give();
            return rc;
        }
        ipa__set_notify_state_change(NULL); /** TODO: Filter by eimId */
        /* Check if we need to process the eIM Package */
        if (EIM_PACKAGE_ERROR_CHOICE_GEPR == get_eim_package_response.choice) {
            // Handle error response
            if (EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE == get_eim_package_response.value.eim_package_error) {
                LOGI("[ESipa] noEimPackageAvailable received");
                eim_package_available = false;
            } else {
                LOGW("[esipa_sync__execute_eim_package_retrieval] eimPackageError(%d) received on GetEimPackageResponse", get_eim_package_response.value.eim_package_error);
#ifdef EXTRA_FEATURE_ESIPA_RETRY_ON_ERROR
                LOGD("[esipa_sync__execute_eim_package_retrieval] Retrying requesting eIM packages");
#else
                eim_package_available = false;
#endif
            }
        } else {
            // Process eIM Package
            if (eOk == (rc = esipa_sync__execute_get_eim_package_response(me, &get_eim_package_response))) {
                LOGI("[ESipa] eIM Package successfully processed, continuing with the eIM Package Retrieval procedure");
            } else {
                LOGE("[esipa_sync__execute_eim_package_retrieval] Error on process the eIM Package, rc %d.");
                eim_package_available = false; // To avoid request again the same package
            }
        }
        /* Free the GetEimPackageResponse */
        esipa_sync__free_get_eim_package_response(&get_eim_package_response);
    }
    
    LOGI("[ESipa] eIM Package Retrieval procedure finished"); // Although errors may have appeared when processing the eIM responses, at this point we can conclude that the procedure has been finished.
    ipa__give();
    return eOk;
}

static ErrCode esipa_sync__execute_get_eim_package_response(esipa_sync_t * const me, get_eim_package_response_t* req) {
    /* Check input parameters */
    if (!req) {
        LOGE("[esipa_sync__execute_get_eim_package_response] The GetEimPackageResponse object is null");
        return eBadArg;
    }

    /* Execute the request */
    switch (req->choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_GEPR:
        LOGD("[esipa_sync__execute_get_eim_package_response] The GetEimPackageResponse is an euiccPackageRequest");
        return esipa_sync__execute_euicc_package_request(me, req);
    case IPA_EUICC_DATA_REQUEST_CHOICE_GEPR:
        LOGD("[esipa_sync__execute_get_eim_package_response] The GetEimPackageResponse is a ipaEuiccDataRequest");
        return esipa_sync__execute_ipa_euicc_data_request(me, req);
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR:
        LOGD("[esipa_sync__execute_get_eim_package_response] The GetEimPackageResponse is a profileDownloadTriggerRequest");
        return esipa_sync__execute_profile_download_trigger_request(me, req);
    case EIM_PACKAGE_ERROR_CHOICE_GEPR:
        LOGD("[esipa_sync__execute_get_eim_package_response] The GetEimPackageResponse is a eimPackageError(%d)", req->value.eim_package_error);
        return eOk; // Use case not handled in this function
    default:
        LOGE("[esipa_sync__execute_get_eim_package_response] Unknown GetEimPackageResponse CHOICE %d", req->choice);
        return eBadArg;
    }
}

static ErrCode esipa_sync__execute_euicc_package_request(esipa_sync_t * const me, get_eim_package_response_t* req) {
    ErrCode rc;
    provide_eim_package_result_t res = { 0 };

    /* Check input parameters */
    if (!req) {
        LOGE("[esipa_sync__execute_euicc_package_request] The GetEimPackageResponse object is null");
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res);
    }
    if (req->choice != EUICC_PACKAGE_REQUEST_CHOICE_GEPR) {
        LOGE("[esipa_sync__execute_euicc_package_request] The GetEimPackageResponse CHOICE (%d) is not an euiccPackageRequest", req->choice);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res);
    }

    /* Execute the eUICC Package */
    if ((rc = ipa__euicc_package(&req->value.euicc_package_request, &res.eim_package_result.value.epr_and_notifications)) != eOk) {
        LOGE("[esipa_sync__execute_euicc_package_request] Error on execute the eUICC Package on the IPA, rc %d", rc);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR, &res);
    }

    /* Populate the response object */
    if (res.eim_package_result.value.epr_and_notifications.notification_list || res.eim_package_result.value.epr_and_notifications.notification_list_size > 0) {
        res.eim_package_result.choice = EPR_AND_NOTIFICATIONS_CHOICE_PEPR;
    } else {
        // Is safe to change the choice since the region of the memory where the EuiccPackageResult is stored is the same
        res.eim_package_result.choice = EUICC_PACKAGE_RESULT_CHOICE_PEPR;
    }

    /* Send the response */
    rc = esipa_sync__execute_eim_package_result(me, &res);
    ipa__free_epr_and_notifications(&res.eim_package_result.value.epr_and_notifications);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_euicc_package_request] Error on execute the eIM Package Result generated, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_sync__execute_ipa_euicc_data_request(esipa_sync_t * const me, get_eim_package_response_t* req) {
    ErrCode rc;
    provide_eim_package_result_t res = { 0 };

    /* Check input parameters */
    if (!req) {
        LOGE("[esipa_sync__execute_ipa_euicc_data_request] The GetEimPackageResponse object is null");
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res);
    }
    if (req->choice != IPA_EUICC_DATA_REQUEST_CHOICE_GEPR) {
        LOGE("[esipa_sync__execute_ipa_euicc_data_request] The GetEimPackageResponse CHOICE (%d) is not a ipaEuiccDataRequest", req->choice);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res);
    }

    /* Execute the IPA eUICC data request */
    if ((rc = ipa__ipa_euicc_data(&req->value.ipa_euicc_data_request, &res.eim_package_result.value.ipa_euicc_data_response)) != eOk) {
        LOGE("[esipa_sync__execute_ipa_euicc_data_request] Error on execute the IPA eUICC data request on the IPA, rc %d", rc);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR, &res);
    }

    /* Populate the response object */
    res.eim_package_result.choice = IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR;

    /* Send the response */
    rc = esipa_sync__execute_eim_package_result(me, &res);
    ipa__free_ipa_euicc_data_response(&res.eim_package_result.value.ipa_euicc_data_response);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_ipa_euicc_data_request] Error on execute the eIM Package Result generated, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_sync__execute_profile_download_trigger_request(esipa_sync_t * const me, get_eim_package_response_t* req) {

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    return esipa_sync__execute_indirect_profile_download_trigger_request(me, &req->value.profile_download_trigger_request);
#else
    ErrCode rc;
    handle_notification_esipa_t res = { 0 };

    /* Check input parameters */
    if (!req) {
        LOGE("[esipa_sync__execute_profile_download_trigger_request] The GetEimPackageResponse object is null");
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res.value.provide_eim_package_result);
    }
    if (req->choice != PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR) {
        LOGE("[esipa_sync__execute_profile_download_trigger_request] The GetEimPackageResponse CHOICE (%d) is not a profileDownloadTriggerRequest", req->choice);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNKNOWN_PACKAGE, &res.value.provide_eim_package_result);
    }

    /* Execute the Profile Download Trigger request */
    if ((rc = ipa__profile_download_trigger(&req->value.profile_download_trigger_request, &res.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result)) != eOk) {
        LOGE("[esipa_sync__execute_profile_download_trigger_request] Error on execute the Profile Download Trigger request on the IPA, rc %d", rc);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR, &res.value.provide_eim_package_result);
    }

    /* Populate the response object */
    res.value.provide_eim_package_result.eim_package_result.choice = PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR;
    if ((rc = esipa__set_provide_eim_package_result_eid_value(&res.value.provide_eim_package_result)) != eOk) {
        LOGE("[esipa_sync__execute_profile_download_trigger_request] Error on set the eidValue in the ProvideEimPackageResult, rc %d", rc);
        ipa__free_profile_download_trigger_result(&res.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result);
        return esipa_sync__execute_eim_package_result_on_error(me, req, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR, &res.value.provide_eim_package_result);
    }
    res.choice = PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE;

    /* Send the response */
    rc = esipa_sync__send_handle_notification_esipa(me, &res);
    ipa__free_profile_download_trigger_result(&res.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_profile_download_trigger_request] Error on send the profileDownloadTriggerResult notification, rc %d", rc);
        return rc;
    }

    return eOk;
#endif
}

static ErrCode esipa_sync__execute_eim_package_result(esipa_sync_t * const me, provide_eim_package_result_t* req) {
    ErrCode rc;
    provide_eim_package_result_response_t res = { 0 };

    /* Set the EID */
    if ((rc = esipa__set_provide_eim_package_result_eid_value(req)) != eOk) {
        LOGE("[esipa_sync__execute_eim_package_result] Error on set the eidValue in the ProvideEimPackageResult, rc %d", rc);
        return rc;
    }

    /* Send the ProvideEimPackageResult */
    if ((rc = esipa_sync__send_provide_eim_package_result(me, req, &res)) != eOk) {
        LOGE("[esipa_sync__execute_eim_package_result] Error on send the ProvideEimPackageResult, rc %d", rc);
        return rc;
    }

    /* Execute the ProvideEimPackageResultResponse */
    rc = esipa__execute_provide_eim_package_result_response(&res);
    esipa_sync__free_provide_eim_package_result_response(&res);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_eim_package_result] Error on execute the ProvideEimPackageResultResponse, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_sync__execute_eim_package_result_on_error(esipa_sync_t * const me, const get_eim_package_response_t* req, const eim_package_error_from_ipa_to_eim_t error, provide_eim_package_result_t* in) {
    ErrCode rc;

    /* Populate the EimPackageResult */
    if ((rc = esipa__set_eim_package_result_response_error(req, error, &in->eim_package_result)) != eOk) {
        LOGE("[esipa_sync__execute_eim_package_result_on_error] Error on set the error in the EimPackageResult, rc %d", rc);
        return rc;
    }

    /* Execute the EimPackageResult */
    if ((rc = esipa_sync__execute_eim_package_result(me, in)) != eOk) {
        LOGE("[esipa_sync__execute_eim_package_result_on_error] Error on execute an EimPackageResult after an error detection, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_sync__send_get_eim_package_request(esipa_sync_t * const me, get_eim_package_response_t* out) {
    ErrCode rc;
    get_eim_package_request_t request_obj = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* request;
    uint32_t request_size;
    uint32_t response_size;

    /* Check input parameters */
    if (!out) {
        LOGE("[esipa_sync__send_get_eim_package_request] The GetEimPackageResponse object is null");
        return eBadArg;
    }

    /* Populate the GetEimPackageRequest object */
    if ((rc = esipa__get_eim_package_request((esipa_t*) me, &request_obj)) != eOk) {
        LOGE("[esipa_sync__send_get_eim_package_request] Error on populate the GetEimPackageRequest object, rc %d", rc);
        return rc;
    }

    esipa_display__get_eim_package_request(&request_obj);

    /* Generate the GetEimPackageRequest message */
    if ((request_size = esipa_data_binding__generate_get_eim_package_request(NULL, 0, data_binding, &request_obj)) < 0) {
        LOGE("[esipa_sync__send_get_eim_package_request] Error on calculate the size of the GetEimPackageRequest message, err %ld", request_size);
        return eFatal;
    }

    request = M_malloc(request_size);
    if (!request) {
        LOGE("[esipa_sync__send_get_eim_package_request] Can not allocate data to the GetEimPackageRequest message");
        return eNoMem;
    }

    if ((request_size = esipa_data_binding__generate_get_eim_package_request(request, request_size, data_binding, &request_obj)) < 0) {
        LOGE("[esipa_sync__send_get_eim_package_request] Error on generate the GetEimPackageRequest message, err %ld", request_size);
        M_free(request);
        return eFatal;
    }

    /* Send the GetEimPackageRequest message */
    LOGI("ESipa.GetEimPackage");
    rc = esipa_sync__send_message(me, ESIPA_PATH_GET_EIM_PACKAGE, &request, &request_size, (uint8_t**) &out->context, &response_size);
    M_free(request);
    request = NULL;
    request_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_get_eim_package_request] Error on send the GetEimPackageRequest, rc %d", rc);
        return rc;
    }
    esipa__set_last_message_sent((esipa_t*) me, GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI);

    /* Parse the GetEimPackageResponse message */
    if ((rc = esipa_data_binding__extract_get_eim_package_response((uint8_t*) out->context, response_size, data_binding, out)) != eOk) {
        LOGE("[esipa_sync__send_get_eim_package_request] Error on parse the GetEimPackageResponse, rc %d", rc);
        M_free(out->context);
        out->context = NULL;
        return rc;
    }

    /* Note: out->context is NOT freed here - it will be freed by esipa_sync__free_get_eim_package_response
     * after the response has been fully processed. The extracted data contains references to this buffer. */

    return eOk;
}

static ErrCode esipa_sync__send_handle_notification_esipa(esipa_sync_t * const me, const handle_notification_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* request;
    uint32_t request_size;
    uint8_t* response;
    uint32_t response_size;

    /* Check input parameters */
    if (!in) {
        LOGE("[esipa_sync__send_handle_notification_esipa] The HandleNotificationEsipa object is null");
        return eBadArg;
    }

    esipa_display__handle_notification_esipa(in);

    /* Generate the HandleNotificationEsipa message */
    if ((request_size = esipa_data_binding__generate_handle_notification_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_handle_notification_esipa] Error on calculate the size of the HandleNotificationEsipa message, err %ld", request_size);
        return eFatal;
    }

    request = M_malloc(request_size);
    if (!request) {
        LOGE("[esipa_sync__send_handle_notification_esipa] Can not allocate data to the HandleNotificationEsipa message");
        return eNoMem;
    }

    if ((request_size = esipa_data_binding__generate_handle_notification_esipa(request, request_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_handle_notification_esipa] Error on generate the HandleNotificationEsipa message, err %ld", request_size);
        M_free(request);
        return eFatal;
    }

    /* Send the HandleNotificationEsipa message */
    LOGI("ESipa.HandleNotification");
    rc = esipa_sync__send_message(me, ESIPA_PATH_HANDLE_NOTIFICATION, &request, &request_size, &response, &response_size);
    M_free(request);
    request = NULL;
    request_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_handle_notification_esipa] Error on send the HandleNotification, rc %d", rc);
        return rc;
    }
    esipa__set_last_message_sent((esipa_t*) me, HANDLE_NOTIFICATION_ESIPA_CHOICE_EMFI);

    /* In this case we don't need to parse anything. Just in case we free the response */
    M_free(response);
    response = 0;
    response_size = 0;

    return eOk;
}

static ErrCode esipa_sync__send_provide_eim_package_result(esipa_sync_t * const me, const provide_eim_package_result_t* in, provide_eim_package_result_response_t* out) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* request;
    uint32_t request_size;
    uint32_t response_size;

    /* Check input parameters */
    if (!in) {
        LOGE("[esipa_sync__send_provide_eim_package_result] The ProvideEimPackageResult object is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa_sync__send_provide_eim_package_result] The ProvideEimPackageResultResponse object is null");
        return eBadArg;
    }

    esipa_display__provide_eim_package_result(in);

    /* Generate the ProvideEimPackageResult message */
    if ((request_size = esipa_data_binding__generate_provide_eim_package_result(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_provide_eim_package_result] Error on calculate the size of the ProvideEimPackageResult message, err %ld", request_size);
        return eFatal;
    }

    request = M_malloc(request_size);
    if (!request) {
        LOGE("[esipa_sync__send_provide_eim_package_result] Can not allocate data to the ProvideEimPackageResult message");
        return eNoMem;
    }

    if ((request_size = esipa_data_binding__generate_provide_eim_package_result(request, request_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_provide_eim_package_result] Error on generate the ProvideEimPackageResult message, err %ld", request_size);
        M_free(request);
        return eFatal;
    }

    /* Send the ProvideEimPackageResult message */
    LOGI("ESipa.ProvideEimPackageResult");
    rc = esipa_sync__send_message(me, ESIPA_PATH_PROVIDE_EIM_PACKAGE_RESULT, &request, &request_size, (uint8_t**) &out->context, &response_size);
    M_free(request);
    request = NULL;
    request_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_provide_eim_package_result] Error on send the ProvideEimPackageResult, rc %d", rc);
        return rc;
    }
    esipa__set_last_message_sent((esipa_t*) me, PROVIDE_EIM_PACKAGE_RESULT_CHOICE_EMFI);

    /* Parse the ProvideEimPackageResultResponse message */
    if ((rc = esipa_data_binding__extract_provide_eim_package_result_response((uint8_t*) out->context, response_size, data_binding, out)) != eOk) {
        LOGE("[esipa_sync__send_provide_eim_package_result] Error on parse the ProvideEimPackageResultResponse, rc %d", rc);
        M_free(out->context);
        out->context = NULL;
        response_size = 0;
        return rc;
    }

    return eOk;
}

static void esipa_sync__free_get_eim_package_response(get_eim_package_response_t* obj) {
    if (obj) {
        M_free(obj->context);
        memset(obj, 0, sizeof(get_eim_package_response_t));
    }
}

static void esipa_sync__free_provide_eim_package_result_response(provide_eim_package_result_response_t* obj) {
    if (obj) {
        M_free(obj->context);
        memset(obj, 0, sizeof(provide_eim_package_result_response_t));
    }
}

/* Virtual Call (Late Binding) */
static ErrCode esipa_sync__send_message(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size) {
    ErrCode rc;

    if (eOk == (rc = (*me->vptr->esipa_sync_send_message) (me, path, request_body, request_body_size, response_body, response_body_size))) {
        if (esipa__update_last_transmission((esipa_t*) me) != eOk) {
            LOGW("[esipa_sync__send_message] Error on update the last transmission. This may result in a new eIM Package Retrieval procedure being triggered in a shorter period of time.");
        }
    } else {
        LOGE("[esipa_sync__send_message] Error on send the ESipa message, rc %d", rc);
    }

    return rc;
}

/* purely-virtual functions should never be called */
static ErrCode esipa_sync__send_message_default(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size) {
    return eNotImpl;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_sync__execute_indirect_profile_download_trigger_request(esipa_sync_t* const me, const profile_download_trigger_request_t* req) {
    ErrCode rc;
    profile_download_trigger_response_result_t profile_download_trigger_response_result = { 0 };

    if (!req) {
        LOGE("[esipa_sync__execute_indirect_profile_download_trigger_request] The ProfileDownloadTriggerRequest object is null");
        return eBadArg;
	}

    if ((rc = ipa__profile_download_trigger(req, &profile_download_trigger_response_result)) != eOk) {
        LOGE("[esipa_sync__execute_indirect_profile_download_trigger_request] Error on execute the Indirect Profile Download Trigger request on the IPA, rc %d", rc);
        return rc;
    }

    /* Validate response contains InitiateAuthenticationRequestEsipa */
    if (profile_download_trigger_response_result.choice != INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE) {
        LOGE("[esipa_sync__execute_indirect_profile_download_trigger_request] Unexpected ProfileDownloadTriggerResponseResult choice %d", profile_download_trigger_response_result.choice);
        ipa__free_profile_download_trigger_response_result(&profile_download_trigger_response_result);
        return eBadArg;
    }

    rc = esipa_sync__execute_indirect_download(me, &profile_download_trigger_response_result.value.initiate_authentication_request_esipa);
    ipa__free_profile_download_trigger_response_result(&profile_download_trigger_response_result);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_indirect_profile_download_trigger_request] Error on execute the Indirect Profile Download request on the IPA, rc %d", rc);
        return rc;
    }

	return eOk;
}

static ErrCode esipa_sync__execute_indirect_download(esipa_sync_t* const me, const initiate_authentication_request_esipa_t* in) {
    ErrCode rc = eOk;
    initiate_authentication_response_esipa_t initiate_authentication_response_esipa = { 0 };
    authenticate_client_request_esipa_t authenticate_client_request_esipa = { 0 };
    authenticate_client_response_esipa_t authenticate_client_response_esipa = { 0 };
    authenticate_client_response_result_esipa_t authenticate_client_response_result_esipa = { 0 };
    cancel_session_response_esipa_t cancel_session_response_esipa = { 0 };
    get_bound_profile_package_response_esipa_t get_bound_profile_package_response_esipa = { 0 };
    get_bound_profile_package_response_result_esipa_t get_bound_profile_package_response_result = { 0 };

    /* Check input parameters */
    if (!in) {
        LOGE("[esipa_sync__execute_indirect_download] The InitiateAuthenticationRequestEsipa object is null");
        return eBadArg;
    }

    /* Execute the Indirect Download procedure */
    // Step 8
    rc = esipa_sync__send_initiate_authentication_request_esipa(me, in, &initiate_authentication_response_esipa);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_indirect_download] Error on execute InitiateAuthenticationRequestEsipa, rc %d", rc);
        goto cleanup;
    }

    /* Execute the use case in the IPA */
    // Step 11-12
    rc = ipa__initiate_authentication_response(&initiate_authentication_response_esipa, &authenticate_client_request_esipa);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_indirect_download] Error executing InitiateAuthenticationResponseEsipa against the IPA, rc %d", rc);
        goto cleanup;
    }

    // Step 13-15
    rc = esipa_sync__send_authenticate_client_request_esipa(me, &authenticate_client_request_esipa, &authenticate_client_response_esipa);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_indirect_download] Error executing SendAuthenticateClientRequestEsipa against the IPA, rc %d", rc);
        goto cleanup;
    }

	// Step 16-17
    rc = ipa__authenticate_client_response(&authenticate_client_response_esipa, &authenticate_client_response_result_esipa);
    if (rc != eOk) {
        LOGE("[esipa_sync__execute_indirect_download] Error executing ipa__authenticate_client_response, rc %d", rc);
        goto cleanup;
    }

    switch (authenticate_client_response_result_esipa.choice) {
    case OK_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        LOGT("[esipa_sync__execute_indirect_download] AuthenticateClientResponseEsipa contains OK_AUTHENTICATE_CLIENT_RESULT_CHOICE");
        goto cleanup;
    case PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE:
        LOGW("[esipa_sync__execute_indirect_download] PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE not supported in sync indirect flow, ignoring");
        goto cleanup;
    case GET_BOUND_PROFILE_PACKAGE_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        if ((rc = esipa_sync__send_get_bound_profile_package_request_esipa(me, &authenticate_client_response_result_esipa.value.get_bound_profile_package_request_esipa, &get_bound_profile_package_response_esipa)) != eOk) {
            LOGE("[esipa_sync__execute_indirect_download] Error executing GetBoundProfilePackageRequestEsipa against the eIM, rc %d", rc);
            goto cleanup;
        }

        esipa_display__get_bound_profile_package_response_esipa(&get_bound_profile_package_response_esipa);

        /* Execute the get bound profile package*/
        if ((rc = ipa__get_bound_profile_package_response(&get_bound_profile_package_response_esipa, &get_bound_profile_package_response_result)) != eOk) {
            LOGE("[esipa_sync__execute_indirect_download] Error executing the GetBoundProfilePackageResponseEsipa against the IPA, rc %d", rc);
            goto cleanup;
        }
        /* Send the response to the eIM */
        switch (get_bound_profile_package_response_result.choice) {
        case CANCEL_SESSION_REQUEST_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
            if ((rc = esipa_sync__send_cancel_session_request_esipa(me, &get_bound_profile_package_response_result.value.cancel_session_request_esipa, &cancel_session_response_esipa)) != eOk) {
                LOGE("[esipa_sync__execute_indirect_download] Error sending the cancelSessionRequestEsipa to the eIM, rc %d", rc);
            }
            break;
        case HANDLE_NOTIFICATION_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
            if ((rc = esipa_sync__send_handle_notification_esipa(me, &get_bound_profile_package_response_result.value.handle_notification_esipa)) != eOk) {
                LOGE("[esipa_sync__execute_indirect_download] Error sending the handleNotificationEsipa to the eIM, rc %d", rc);
            }
            break;
        default:
            LOGE("[esipa_sync__execute_indirect_download] Unknown result choice %d", get_bound_profile_package_response_result.choice);
            rc = eFatal;
            break;
        }
        ipa__free_get_bound_profile_package_response_result_esipa(&get_bound_profile_package_response_result);
        goto cleanup;
    case CANCEL_SESSION_REQUEST_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        rc = esipa_sync__send_cancel_session_request_esipa(me, &authenticate_client_response_result_esipa.value.cancel_session_request_esipa, &cancel_session_response_esipa);
        goto cleanup;
    default:
        LOGE("[esipa_sync__execute_indirect_download] Unknown choice %d", authenticate_client_response_result_esipa.choice);
    }

cleanup:
    /* Free the extracted data structures (these functions also free the context buffers) */
    ipa__free_initiate_authentication_response_esipa(&initiate_authentication_response_esipa);
    ipa__free_authenticate_client_request_esipa(&authenticate_client_request_esipa);
    ipa__free_authenticate_client_response_esipa(&authenticate_client_response_esipa);
    ipa__free_authenticate_client_response_result_esipa(&authenticate_client_response_result_esipa);
    ipa__free_get_bound_profile_package_response_esipa(&get_bound_profile_package_response_esipa);
    ipa__free_cancel_session_response_esipa(&cancel_session_response_esipa);
    return rc;
}

static ErrCode esipa_sync__send_get_bound_profile_package_request_esipa(esipa_sync_t* const me, const get_bound_profile_package_request_esipa_t* in, get_bound_profile_package_response_esipa_t* out) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*)me);
    uint8_t* message = NULL;
    uint32_t message_size;
    uint32_t response_size;

    if (!in) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] GetBoundProfilePackageRequestEsipa object is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] GetBoundProfilePackageResponseEsipa object is null");
        return eBadArg;
    }

    esipa_display__get_bound_profile_package_request_esipa(in);

    /* Generate the GetBoundProfilePackageRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_get_bound_profile_package_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] Error calculating the size of the GetBoundProfilePackageRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] Can not allocate data to the GetBoundProfilePackageRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_get_bound_profile_package_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] Error on generating the GetBoundProfilePackageRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the GetBoundProfilePackageRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_sync__send_get_bound_profile_package_request_esipa] GetBoundProfilePackageRequestEsipa", message, message_size);
    rc = esipa_sync__send_message(me, ESIPA_PATH_GET_BOUND_PROFILE_PACKAGE, &message, &message_size, (uint8_t**) &out->context, &response_size);
    M_free(message);
    message = NULL;
    message_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] Error on send the GetBoundProfilePackageRequestEsipa, rc %d", rc);
        goto cleanup;
    }
    esipa__set_last_message_sent((esipa_t*)me, GET_BOUND_PROFILE_PACKAGE_REQUEST_ESIPA_CHOICE_EMFI);

    /* Parse the GetBoundProfilePackageResponseEsipa message */
    rc = esipa_data_binding__extract_get_bound_profile_package_response_esipa((uint8_t*) out->context, response_size, data_binding, out);
    if (rc != eOk) {
        LOGE("[esipa_sync__send_get_bound_profile_package_request_esipa] Error on parse the GetBoundProfilePackageResponseEsipa, rc %d", rc);
        goto cleanup;
    }

    /* Note: out->context is NOT freed here - it will be freed by the caller
     * after the response has been fully processed. The extracted data contains references to this buffer. */

    return eOk;

cleanup:
    if (out->context) {
        M_free(out->context);
        out->context = NULL;
    }
    return rc;
}

static ErrCode esipa_sync__send_cancel_session_request_esipa(esipa_sync_t* const me, const cancel_session_request_esipa_t* in, cancel_session_response_esipa_t* out) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*)me);
    uint8_t* message = NULL;
    uint32_t message_size;
    uint32_t response_size;

    if (!in) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] CancelSessionRequestEsipa object is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] CancelSessionResponseEsipa object is null");
        return eBadArg;
    }
    esipa_display__cancel_session_request_esipa(in);

    /* Generate the CancelSessionRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_cancel_session_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] Error calculating the size of the CancelSessionRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] Can not allocate data to the CancelSessionRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_cancel_session_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] Error on generating the CancelSessionRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the CancelSessionRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_sync__send_cancel_session_request_esipa] CancelSessionRequestEsipa", message, message_size);
    rc = esipa_sync__send_message(me, ESIPA_PATH_CANCEL_SESSION, &message, &message_size, (uint8_t**) &out->context, &response_size);
    M_free(message);
    message = NULL;
    message_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] Error on send the CancelSessionRequestEsipa, rc %d", rc);
        goto cleanup;
    }
    esipa__set_last_message_sent((esipa_t*)me, CANCEL_SESSION_REQUEST_ESIPA_CHOICE_EMFI);

    /* Parse the CancelSessionResponseEsipa message */
    rc = esipa_data_binding__extract_cancel_session_response_esipa((uint8_t*) out->context, response_size, data_binding, out);
    if (rc != eOk) {
        LOGE("[esipa_sync__send_cancel_session_request_esipa] Error on parse the CancelSessionResponseEsipa, rc %d", rc);
        goto cleanup;
    }

    /* Note: out->context is NOT freed here - it will be freed by the caller
     * after the response has been fully processed. The extracted data contains references to this buffer. */

    return eOk;

cleanup:
    if (out->context) {
        M_free(out->context);
        out->context = NULL;
    }
    return rc;
}

static ErrCode esipa_sync__send_initiate_authentication_request_esipa(esipa_sync_t* const me, const initiate_authentication_request_esipa_t* in, initiate_authentication_response_esipa_t* out) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*)me);
    uint8_t* message = NULL;
    uint32_t message_size;
    uint32_t response_size;

    if (!in) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] InitiateAuthenticationRequestEsipa object is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] InitiateAuthenticationResponseEsipa object is null");
        return eBadArg;
    }
    esipa_display__initiate_authentication_request_esipa(in);

    /* Generate the InitiateAuthenticationRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_initiate_authentication_request(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] Error calculating the size of the InitiateAuthenticationRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] Can not allocate data to the InitiateAuthenticationRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_initiate_authentication_request(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] Error on generating the InitiateAuthenticationRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the InitiateAuthenticationRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_sync__send_initiate_authentication_request_esipa] InitiateAuthenticationRequestEsipa", message, message_size);
    rc = esipa_sync__send_message(me, ESIPA_PATH_INITIATE_AUTHENTICATION, &message, &message_size, (uint8_t**) &out->context, &response_size);
    M_free(message);
    message = NULL;
    message_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] Error sending the InitiateAuthenticationRequestEsipa to the eIM, rc %d", rc);
        goto cleanup;
    }
    esipa__set_last_message_sent((esipa_t*) me, INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE_EMFI);

    /* Parse the InitiateAuthenticationResponseEsipa */
    rc = esipa_data_binding__extract_initiate_authentication_response_esipa((uint8_t*) out->context, response_size, data_binding, out);
    if (rc != eOk) {
        LOGE("[esipa_sync__send_initiate_authentication_request_esipa] Error parsing the InitiateAuthenticationResponseEsipa message, rc %d", rc);
        goto cleanup;
    }

    /* Note: out->context is NOT freed here - it will be freed by the caller
     * after the response has been fully processed. The extracted data contains references to this buffer. */

    LOGI("[ESipa] InitiateAuthentication executed successfully");
    return eOk;

cleanup:
    if (out->context) {
        M_free(out->context);
        out->context = NULL;
    }
    return rc;
}

static ErrCode esipa_sync__send_authenticate_client_request_esipa(esipa_sync_t* const me, const authenticate_client_request_esipa_t* in, authenticate_client_response_esipa_t* out) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*)me);
    uint8_t* message = NULL;
    uint32_t message_size;
    uint32_t response_size;

    if (!in) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] AuthenticateClientRequestEsipa object is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] AuthenticateClientResponseEsipa object is null");
        return eBadArg;
    }

    esipa_display__authenticate_client_request_esipa(in);

    /* Generate the AuthenticateClientRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_authenticate_client_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] Error calculating the size of the AuthenticateClientRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] Can not allocate data to the AuthenticateClientRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_authenticate_client_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] Error on generating the AuthenticateClientRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the AuthenticateClientRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_sync__send_authenticate_client_request_esipa] AuthenticateClientRequestEsipa", message, message_size);
    rc = esipa_sync__send_message(me, ESIPA_PATH_AUTHENTICATE_CLIENT, &message, &message_size, (uint8_t**) &out->context, &response_size);
    M_free(message);
    message = NULL;
    message_size = 0;
    if (rc != eOk) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] Error sending the AuthenticateClientRequestEsipa to the eIM, rc %d", rc);
        goto cleanup;
    }
    esipa__set_last_message_sent((esipa_t*)me, AUTHENTICATE_CLIENT_REQUEST_ESIPA_CHOICE_EMFI);

    /* Parse the AuthenticateClientResponseEsipa */
    rc = esipa_data_binding__extract_authenticate_client_response_esipa((uint8_t*) out->context, response_size, data_binding, out);
    if (rc != eOk) {
        LOGE("[esipa_sync__send_authenticate_client_request_esipa] Error parsing the AuthenticateClientResponseEsipa message, rc %d", rc);
        goto cleanup;
    }

    /* Note: out->context is NOT freed here - it will be freed by the caller
     * after the response has been fully processed. The extracted data contains references to this buffer. */

    LOGI("[ESipa] AuthenticateClient executed successfully");
    return eOk;

cleanup:
    if (out->context) {
        M_free(out->context);
        out->context = NULL;
    }
    return rc;
}
#endif /* IPA_FEATURE_INDIRECT_DOWNLOAD */

#endif /* defined(ENABLE_HTTP_ESIPA) */