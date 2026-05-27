/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#if defined(ENABLE_MQTT) || defined(ENABLE_LWM2M)
#include "esipa_async.h"
#include "esipa_data_binding.h"
#include "esipa_display.h"
#include "ipa.h"
#include "log.h"
#include "ipa_core.h"
#include "memory_manager.h"

/* Subclass implementation of the parent virtual functions */
static ErrCode esipa_async__init(esipa_t* const me);

/* Functions to handle the connection */
static ErrCode esipa_async__connect(esipa_async_t* const me);
ErrCode esipa_async__disconnect(esipa_async_t* const me);
static bool esipa_async__keep_alive(esipa_async_t* const me);

/* Generic funtion to send messages */
static ErrCode esipa_async__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size);

/* Funtions to trigger ESipa procedures */
static ErrCode esipa_async__execute_eim_package_retrieval(esipa_async_t * const me);
static ErrCode esipa_async__execute_profile_download_trigger_request(esipa_async_t* const me, const profile_download_trigger_request_t* profile_download_trigger_request);

/* Funtions to execute EsipaMessageFromEimToIpa */
static ErrCode esipa_async__execute_transfer_eim_package_request(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size);
static ErrCode esipa_async__execute_get_eim_package_response(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size);
static ErrCode esipa_async__execute_provide_eim_package_result_response(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_async__execute_initiate_authentication_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size);
static ErrCode esipa_async__execute_authenticate_client_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size);
static ErrCode esipa_async__execute_get_bound_profile_package_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size);
#endif

/* Functions to send EsipaMessageFromIpaToEim */
static ErrCode esipa_async__send_get_eim_package_request(esipa_async_t * const me);
static ErrCode esipa_async__send_handle_notification_esipa(esipa_async_t * const me, const handle_notification_esipa_t* in);
static ErrCode esipa_async__send_transfer_eim_package_response(esipa_async_t * const me, const transfer_eim_package_response_t* in);
static ErrCode esipa_async__send_provide_eim_package_result(esipa_async_t * const me, const provide_eim_package_result_t* in);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_async__send_initiate_authentication_request_esipa(esipa_async_t * const me, const initiate_authentication_request_esipa_t* in);
static ErrCode esipa_async__send_authenticate_client_request_esipa(esipa_async_t * const me, const authenticate_client_request_esipa_t* in);
static ErrCode esipa_async__send_get_bound_profile_package_request_esipa(esipa_async_t* const me, const get_bound_profile_package_request_esipa_t* in);
static ErrCode esipa_async__send_cancel_session_request_esipa(esipa_async_t * const me, const cancel_session_request_esipa_t* in);
static ErrCode esipa_async__send_profile_download_trigger_result_indirect_notification(esipa_async_t * const me, const profile_download_trigger_result_t* in);
static ErrCode esipa_async__send_profile_download_trigger_response_result(esipa_async_t * const me, const profile_download_trigger_response_result_t* in);
#endif

/* purely-virtual functions should never be called */
static ErrCode esipa_async__connect_default(esipa_async_t* const me);
static ErrCode esipa_async__disconnect_default(esipa_async_t* const me);
static bool esipa_async__keep_alive_default(esipa_async_t* const me);
static ErrCode esipa_async__send_message_default(esipa_async_t* const me, uint8_t** message, uint32_t* message_size);


void esipa_async__ctor(esipa_async_t* const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, int port, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size, gsma_data_binding_t data_binding) {
    static struct esipa_vtbl_s const esipa_vtbl = {  /* vtbl of the ESipa class */
        &esipa_async__init
    };
    esipa__ctor(&me->super, eim_id, eim_id_size, fqdn, port, data_binding, trusted_certificate_tls, trusted_certificate_tls_size); /* call the superclass constructor */
    me->super.vptr = &esipa_vtbl; /* override the vptr */
    
    /* Set attributes of the class */
    static struct esipa_async_vtbl_s const vtbl = {
        &esipa_async__connect_default,
        &esipa_async__disconnect_default,
        &esipa_async__keep_alive_default,
        &esipa_async__send_message_default
    };
    me->vptr = &vtbl; // The ESipa Async subclass shall overwrite this virtual table

    me->is_connected = false;
    me->on_retrieval_procedure = false;
}

void esipa_async__destroy(esipa_async_t * const me) {
    ErrCode rc;

    /* Diconnect in case is still connected */
    if (me->is_connected) {
        if ((rc = esipa_async__disconnect(me)) != eOk) {
            LOGW("[esipa_async__destroy] Error on disconnect the ESipa Async, rc %d", rc); // Should we retry it?
        }
    }

    /* Reset the attributes of the subclass */
    me->is_connected = false;
    me->on_retrieval_procedure = false;

    /* Destroy the parent instance */
    esipa__destroy((esipa_t*) me);
}

ErrCode esipa_async__connected(esipa_async_t* const me) {
    ErrCode rc;

    if (!me) {
        LOGE("[esipa_async__connected] The ESipa Async instance is null");
        return eBadArg;
    }

    LOGD("[esipa_async__connected] ESipa Async interface connected");
    me->is_connected = true;

    if ((rc = esipa_async__execute_eim_package_retrieval(me)) != eOk) {
        LOGW("[esipa_async__connected] Error on execute the eIM Package Retrieval Procedure, rc %d", rc); // A retry will be done so we don't need to return an error
    }

    return eOk;
}

ErrCode esipa_async__connection_lost(esipa_async_t* const me) {
    state_change_cause_t cause = STATE_CHANGE_CAUSE_UNDEFINED; // No specific cause for disconnection

    if (!me) {
        LOGE("[esipa_async__connection_lost] The ESipa Async instance is null");
        return eBadArg;
    }
    
    LOGD("[esipa_async__connection_lost] ESipa Async interface connection lost");
    me->is_connected = false;

    ipa__set_notify_state_change(&cause);

    return eOk;
}

ErrCode esipa_async__execute_message(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    esipa_message_from_eim_to_ipa_choice_t choice;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

#ifdef DEBUG_ESIPA
    LOG_DATA(eLogInfo, "ESipa <<", message, message_size);
#else
    LOG_DATA(eLogDebug, "[esipa_async__execute_message] EsipaMessageFromEimToIpa", message, message_size);
#endif

    /* Check if the IPA is available to process the message */
    if (ipa__take() != 0) {
        LOGW("[esipa_async__execute_message] The IPA is not available to process the message. The message that has arrived will be discarded and the IPA will initiate a new communication to re-request it.");
        /* This will force a new trigger of eIM Package Retrieval Procedure when the IPA is available again */
        me->on_retrieval_procedure = false;
        state_change_cause_t cause = STATE_CHANGE_CAUSE_UNDEFINED;
        ipa__set_notify_state_change(&cause); // TODO: Filter by eimId
        return eFatal;
    }

    /* Update the last transmission clock */
    if ((rc = esipa__update_last_transmission((esipa_t*) me)) != eOk) {
        LOGW("[esipa_async__execute_message] Error on update the last transmission clock, rc %d", rc);
    }

    if ((rc = esipa_data_binding__get_esipa_message_from_eim_to_ipa_choice(message, message_size, data_binding, esipa__get_last_message_sent((esipa_t*) me), &choice)) != eOk) {
        LOGE("[esipa_async__execute_message] Error on get the EsipaMessageFromEimToIpa CHOICE, rc %d", rc);
        ipa__give();
        return rc;
    }

    switch (choice)
    {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    case INITIATE_AUTHENTICATION_RESPONSE_ESIPA_CHOICE:
        LOGI("[ESipa]\tInitiateAuthenticationResponseEsipa message received");
        rc = esipa_async__execute_initiate_authentication_response_esipa(me, message, message_size);
        break;
    case AUTHENTICATE_CLIENT_RESPONSE_ESIPA_CHOICE:
        LOGI("[ESipa]\tAuthenticateClientResponseEsipa message received");
        rc = esipa_async__execute_authenticate_client_response_esipa(me, message, message_size);
        break;
    case GET_BOUND_PROFILE_PACKAGE_RESPONSE_ESIPA_CHOICE:
        LOGI("[ESipa]\tGetBoundProfilePackageResponseEsipa message received");
        rc = esipa_async__execute_get_bound_profile_package_response_esipa(me, message, message_size);
        break;
    case CANCEL_SESSION_RESPONSE_ESIPA_CHOICE:
        LOGI("[ESipa]\tCancelSessionResponseEsipa message received");
        rc = esipa__execute_cancel_session_response_esipa((esipa_t*) me, message, message_size);
        break;
#endif
    case TRANSFER_EIM_PACKAGE_REQUEST_CHOICE:
        LOGI("[ESipa]\tTransferEimPackageRequest message received");
        rc = esipa_async__execute_transfer_eim_package_request(me, message, message_size);
        break;
    case GET_EIM_PACKAGE_RESPONSE_CHOICE:
        LOGI("[ESipa]\tGetEimPackageResponse message received");
        rc = esipa_async__execute_get_eim_package_response(me, message, message_size);
        break;
    case PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE:
        LOGI("[ESipa]\tProvideEimPackageResultResponse message received");
        rc = esipa_async__execute_provide_eim_package_result_response(me, message, message_size);
        break;
    default:
        LOGE("[esipa_async__execute_message] Unknown EsipaMessageFromEimToIpa CHOICE %04X", choice);
        rc = eFatal;
        break;
    }

    ipa__give();
    return rc;
}

static ErrCode esipa_async__init(esipa_t* const me) {
    ErrCode rc;
    clock_data_t current_clock;
    clock_data_t last_transmission_clock;
    esipa_async_t* const me_ = (esipa_async_t*) me; /* explicit downcast */

    if (!me) {
        LOGE("[esipa_async__init] The ESipa Async instance is null");
        return eBadArg;
    }

    if ((rc = esipa_async__connect(me_)) != eOk) {
        LOGE("[esipa_async__init] Error on connect the ESipa Async instance, rc %d", rc);
        return rc;
    }

    notify_app(IPA_EVENT_SERVICE_START_SUCCESS, NULL);

    while (esipa_async__keep_alive(me_) && !ipa__get_ipa_exit() && me_->is_connected) {
        /* Get clocks to calculate the time elapsed between now and the last transmission */
        if (timer__get_clock_data(&current_clock) < 0) {
            LOGW("[esipa_async__init] Error on retrieve he current clock");
            continue; // Try to get the current clock in the next iteration
        }

        if ((rc = esipa__get_last_transmission((esipa_t*)me, &last_transmission_clock)) != eOk) {
            LOGW("[esipa_async__init] Error on retrieve he last transmission clock");
            continue; // Try to get the last transmission clock in the next iteration
        }

        /** Check if we need to trigger a eIM Package Retrieval Procedure. TODO: Check the NotifyStateChange filtering by eimId */
        // LOGT("NotifyStateChange %d, simAvailable %d, isConnected %d, onEimPackageRetrievalProcedure %d, lastTransmission %lld, currentTime %lld", ipa__get_notify_state_change(), ipa__is_available(), me->is_connected, me->on_retrieval_procedure, last_transmission_clock.tv_sec, current_clock.tv_sec);
        if (ipa__get_notify_state_change(NULL) && !me_->on_retrieval_procedure && ipa__is_available() && me_->is_connected && (current_clock.tv_sec - last_transmission_clock.tv_sec) >= 30) {
            LOGD("[esipa_async__init] The eIM Package Retrieval Procedure will be executed");
            if ((rc = esipa_async__execute_eim_package_retrieval(me_)) != eOk) {
                LOGW("[esipa_async__init] Failed execute the eIM Package Retrieval Procedure, rc %d", rc);
            }
        }
    }
    if (me_->is_connected) {
        if ((rc = esipa_async__disconnect(me_)) != eOk) {
            LOGW("[esipa_async__init] Error on disconnect the ESipa Async, rc %d", rc); // Should we retry it?
        }
    }
    return eOk;
}

static ErrCode esipa_async__connect(esipa_async_t* const me) {
    return (*me->vptr->esipa_async_connect) (me); // Call to virtual function (implemented by the subclass)
}

ErrCode esipa_async__disconnect(esipa_async_t* const me) {
    ErrCode rc;

    if (eOk == (rc = (*me->vptr->esipa_async_disconnect) (me))) { // Call to virtual function (implemented by the subclass)
        me->is_connected = false;
    } else {
        LOGE("[esipa_async__disconnect] Error on disconnect the ESipa Async interface");
    }

    return rc;
}

static bool esipa_async__keep_alive(esipa_async_t* const me) {
    return (*me->vptr->esipa_async_keep_alive) (me); // Call to virtual function (implemented by the subclass)
}

static ErrCode esipa_async__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size) {
    ErrCode rc;

    if (!message || message_size == 0) {
        LOGW("[esipa_async__send_message] Empty message to send");
        return eOk;
    }
#ifdef DEBUG_ESIPA
    LOG_DATA(eLogInfo, "ESipa >>", *message, *message_size);
#else
    LOG_DATA(eLogDebug, "[esipa_async__send_message] EsipaMessageFromIpaToEim", *message, *message_size);
#endif

    if ((rc = (*me->vptr->esipa_async_send_message) (me, message, message_size)) != eOk) { // Call to virtual function (implemented by the subclass)
        LOGE("[esipa_async__send_message] Error on send the EsipaMessageFromIpaToEim message, rc %d", rc);
        return rc;
    }

    LOGD("[esipa_async__send_message] EsipaMessageFromIpaToEim sent successfully");
    /* Update the last transmission clock */
    if ((rc = esipa__update_last_transmission((esipa_t*) me)) != eOk) {
        LOGW("[esipa_async__send_message] Error on update the last transmission clock, rc %d", rc);
    }


    return eOk;
}

static ErrCode esipa_async__execute_eim_package_retrieval(esipa_async_t * const me) {
    ErrCode rc;

    if (!me) {
        LOGE("[esipa_async__execute_eim_package_retrieval] ESipa Async instance is null");
        return eBadArg;
    }

    if ((rc = esipa_async__send_get_eim_package_request(me)) != eOk) {
        LOGE("[esipa_async__execute_eim_package_retrieval] Error on send the GetEimPackageRequest, rc %d", rc);
        return rc;
    }

    me->on_retrieval_procedure = true;

    return eOk;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_async__execute_profile_download_trigger_request(esipa_async_t* const me, const profile_download_trigger_request_t* profile_download_trigger_request) {
    ErrCode rc;
    profile_download_trigger_response_result_t result;

    /* Handle the ProfileDownloadTriggerRequest */
    if ((rc = ipa__profile_download_trigger(profile_download_trigger_request, &result)) != eOk) {
        LOGE("[esipa_async__execute_profile_download_trigger_request] Error executing the ProfileDownloadTriggerRequest, rc %d", rc);
        return rc;
    }

    /* Send the InitiateAuthenticationRequestEsipa */
    rc = esipa_async__send_profile_download_trigger_response_result(me, &result);
    ipa__free_profile_download_trigger_response_result(&result);
    if (rc != eOk) {
        LOGE("[esipa_async__execute_profile_download_trigger_request] Error sending response to eIM");
    }
    return rc;
}
#else
static ErrCode esipa_async__execute_profile_download_trigger_request(esipa_async_t * const me, const profile_download_trigger_request_t* profile_download_trigger_request) {
    ErrCode rc;
    handle_notification_esipa_t handle_notification_esipa = { 0 };

    if (!profile_download_trigger_request) {
        LOGE("[esipa_async__execute_profile_download_trigger_request] The ProfileDownloadTriggerRequest object is null");
        return eBadArg;
    }

    /* Execute the profile download trigger */
    if (eOk == (rc = ipa__profile_download_trigger(profile_download_trigger_request, &handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result))) {
        handle_notification_esipa.value.provide_eim_package_result.eim_package_result.choice = PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR;
    } else {
        LOGE("[esipa_async__execute_profile_download_trigger_request] Error executing the Profile Download Trigger request, rc %d", rc);
        handle_notification_esipa.value.provide_eim_package_result.eim_package_result.choice = EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR;
        handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.eim_package_result_response_error.eim_package_result_error_code = EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR;
        /* Copy the transactionId in the error response if is present in the request */
        handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.eim_package_result_response_error.field_is_present.eim_transaction_id = profile_download_trigger_request->field_is_present.eim_transaction_id;
        if (profile_download_trigger_request->field_is_present.eim_transaction_id) {
            memcpy(&handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.eim_package_result_response_error.eim_transaction_id, &profile_download_trigger_request->eim_transaction_id, sizeof(transaction_id_t));
        }
    }

    /* Populate the ProvideEimPackageResult level of the HandleNotification */
    if ((rc = esipa__set_provide_eim_package_result_eid_value(&handle_notification_esipa.value.provide_eim_package_result)) != eOk) {
        LOGE("[esipa_async__execute_profile_download_trigger_request] Error on populate the ProvideEimPackageResult level of the HandleNotification, rc %d", rc);
        goto esipa_async_free_profile_download_trigger_result;
    }

    /* Populate the HandleNotification level */
    handle_notification_esipa.choice = PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE;

    /* Send the notification */
    rc = esipa_async__send_handle_notification_esipa(me, &handle_notification_esipa);

esipa_async_free_profile_download_trigger_result:
    if (handle_notification_esipa.value.provide_eim_package_result.eim_package_result.choice == PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR) {
        ipa__free_profile_download_trigger_result(&handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result);
    }
    return rc;
}
#endif

/* EsipaMessageFromEimToIpa */
static ErrCode esipa_async__execute_transfer_eim_package_request(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    transfer_eim_package_request_t request = { 0 };
    transfer_eim_package_response_t response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_transfer_eim_package_request(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa_async__execute_transfer_eim_package_request] Error parsing TransferEimPackageRequest message, rc %d", rc);
        response.choice = EIM_PACKAGE_ERROR_CHOICE_TEPR;
        response.value.eim_package_error = EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_INVALID_PACKAGE_FORMAT;
        return esipa_async__send_transfer_eim_package_response(me, &response);
    }

    esipa_display__transfer_eim_package_request(&request);

    /* Execute the use case in the IPA and send the response to the eIM */
    switch (request.choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_TEPR:
        if ((rc = ipa__euicc_package(&request.value.euicc_package_request, &response.value.epr_and_notifications)) == eOk) {
            if (response.value.epr_and_notifications.notification_list || response.value.epr_and_notifications.notification_list_size > 0) {
                response.choice = EPR_AND_NOTIFICATIONS_CHOICE_TEPR;
            } else {
                // Is safe to change the choice since the region of the memory where the EuiccPackageResult is stored is the same
                response.choice = EUICC_PACKAGE_RESULT_CHOICE_TEPR;
            }
            rc = esipa_async__send_transfer_eim_package_response(me, &response);
            ipa__free_epr_and_notifications(&response.value.epr_and_notifications);
            return rc;
        } else {
            LOGE("[esipa_async__execute_transfer_eim_package_request] Error executing the Euicc Package on the IPA, rc %d", rc);
            response.choice = EIM_PACKAGE_ERROR_CHOICE_TEPR;
            response.value.eim_package_error = EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR;
            return esipa_async__send_transfer_eim_package_response(me, &response);
        }
    case IPA_EUICC_DATA_REQUEST_CHOICE_TEPR:
        if ((rc = ipa__ipa_euicc_data(&request.value.ipa_euicc_data_request, &response.value.ipa_euicc_data_response)) == eOk) {
            response.choice = IPA_EUICC_DATA_RESPONSE_CHOICE_TEPR;
            rc = esipa_async__send_transfer_eim_package_response(me, &response);
            ipa__free_ipa_euicc_data_response(&response.value.ipa_euicc_data_response);
            return rc;
        } else {
            LOGE("[esipa_async__execute_transfer_eim_package_request] Error executing the Euicc Data on the IPA, rc %d", rc);
            response.choice = EIM_PACKAGE_ERROR_CHOICE_TEPR;
            response.value.eim_package_error = EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR;
            return esipa_async__send_transfer_eim_package_response(me, &response);
        }
    case EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR:
        if ((rc = ipa__eim_acknowledgements(&request.value.eim_acknowledgements)) != eOk) {
            LOGE("[esipa_async__execute_transfer_eim_package_request] Error executing the Eim Acknowledgements on the IPA, rc %d", rc);
        }
        response.choice = EIM_PACKAGE_RECEIVED_CHOICE_TEPR;
        return esipa_async__send_transfer_eim_package_response(me, &response);
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR:
        /* Send to the eIM an eimPackageReceived */
        response.choice = EIM_PACKAGE_RECEIVED_CHOICE_TEPR;
        if ((rc = esipa_async__send_transfer_eim_package_response(me, &response)) != eOk) {
            LOGE("[esipa_async__execute_transfer_eim_package_request] Error sending an eimPackageReceived before start the execution of the Profile Download, rc %d", rc);
        }
        /* Process the Profile Download */
        return esipa_async__execute_profile_download_trigger_request(me, &request.value.profile_download_trigger_request);
    default:
        LOGE("[esipa_async__execute_transfer_eim_package_request] Unknown TransferEimPackageRequest choice %d", request.choice);
        return eBadArg;
    }
}

static ErrCode esipa_async__execute_get_eim_package_response(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size)  {
    ErrCode rc;
    get_eim_package_response_t request = { 0 };
    provide_eim_package_result_t response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    if (!me) {
        LOGE("[esipa_async__execute_get_eim_package_response] The ESipa Async instance is null");
        return eBadArg;
    }

    /** TODO: Set this value with the esipa__set_provide_eim_package_result_eid_value funtion after populate the EimPackageResult */
    ipa__get_eid(&response.eid_value);
    response.field_is_present.eid_value = true;

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_get_eim_package_response(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa_async__execute_get_eim_package_response] Error parsing GetEimPackageResponse message, rc %d", rc);
        response.eim_package_result.choice = EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR;
        response.eim_package_result.value.eim_package_result_response_error.eim_package_result_error_code = EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_INVALID_PACKAGE_FORMAT;
        response.eim_package_result.value.eim_package_result_response_error.field_is_present.eim_transaction_id = false;
        return esipa_async__send_provide_eim_package_result(me, &response);
    }

    esipa_display__get_eim_package_response(&request);

    /* Execute the use case in the IPA and send the response to the eIM */
    switch (request.choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_GEPR:
        if ((rc = ipa__euicc_package(&request.value.euicc_package_request, &response.eim_package_result.value.epr_and_notifications)) == eOk) {
            if (response.eim_package_result.value.epr_and_notifications.notification_list || response.eim_package_result.value.epr_and_notifications.notification_list_size > 0) {
                response.eim_package_result.choice = EPR_AND_NOTIFICATIONS_CHOICE_PEPR;
            } else {
                // Is safe to change the choice since the region of the memory where the EuiccPackageResult is stored is the same
                response.eim_package_result.choice = EUICC_PACKAGE_RESULT_CHOICE_PEPR;
            }
            rc = esipa_async__send_provide_eim_package_result(me, &response);
            ipa__free_epr_and_notifications(&response.eim_package_result.value.epr_and_notifications);
            return rc;
        } else {
            LOGE("[esipa_async__execute_get_eim_package_response] Error executing the Euicc Package on the IPA, rc %d", rc);
            goto get_eim_package_response_send_undefined_error;
        }
    case IPA_EUICC_DATA_REQUEST_CHOICE_GEPR:
        if ((rc = ipa__ipa_euicc_data(&request.value.ipa_euicc_data_request, &response.eim_package_result.value.ipa_euicc_data_response)) == eOk) {
            response.eim_package_result.choice = IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR;
            rc = esipa_async__send_provide_eim_package_result(me, &response);
            ipa__free_ipa_euicc_data_response(&response.eim_package_result.value.ipa_euicc_data_response);
            return rc;
        } else {
            LOGE("[esipa_async__execute_get_eim_package_response] Error executing the Euicc Data on the IPA, rc %d", rc);
            goto get_eim_package_response_send_undefined_error;
        }
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR:
        /* Process the Profile Download */
        return esipa_async__execute_profile_download_trigger_request(me, &request.value.profile_download_trigger_request);
    case EIM_PACKAGE_ERROR_CHOICE_GEPR:
        if (EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE == request.value.eim_package_error) {
            LOGI("[ESipa] noEimPackageAvailable received, eIM Package Retrieval procedure finished");
            me->on_retrieval_procedure = false;
            return eOk;
        } else {
            LOGW("[esipa_async__execute_get_eim_package_response] eimPackageError %d received on GetEimPackageResponse", request.value.eim_package_error);
#ifdef EXTRA_FEATURE_ESIPA_RETRY_ON_ERROR
            LOGD("[esipa_async__execute_get_eim_package_response] Retrying requesting eIM packages");
            return esipa_async__execute_eim_package_retrieval(me);
#else
            LOGI("[ESipa] eIM Package Retrieval procedure finished");
            me->on_retrieval_procedure = false;
            return eOk;
#endif
        }
    default:
        LOGE("[esipa_async__execute_get_eim_package_response] Unknown GetEimPackageResponse choice %d", request.choice);
        return eBadArg;
    }

get_eim_package_response_send_undefined_error:
    if ((rc = esipa__set_eim_package_result_response_error(&request, EIM_PACKAGE_ERROR_FROM_IPA_TO_EIM_UNDEFINED_ERROR, &response.eim_package_result)) != eOk) {
        LOGE("[esipa_async__execute_get_eim_package_response] Error on set the error in the EimPackageResult, rc %d", rc);
        return eFatal;
    }
    return esipa_async__send_provide_eim_package_result(me, &response);
}

static ErrCode esipa_async__execute_provide_eim_package_result_response(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    provide_eim_package_result_response_t provide_eim_package_result_response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_provide_eim_package_result_response(message, message_size, data_binding, &provide_eim_package_result_response)) != eOk) {
        LOGE("[esipa_async__execute_provide_eim_package_result_response] Error parsing the ProvideEimPackageResultResponse message, rc %d", rc);
        return rc;
    }

    esipa_display__provide_eim_package_result_response(&provide_eim_package_result_response);

    /* Execute the use case */
    if ((rc = esipa__execute_provide_eim_package_result_response(&provide_eim_package_result_response)) != eOk) {
        LOGE("[esipa_async__execute_provide_eim_package_result_response] Error on execute the ProvideEimPackageResultResponse message, eIM Package Retrieval procedure aborted. rc %d", rc);
        return rc;
    }

    /* Send the response to the eIM */
    return esipa_async__send_get_eim_package_request(me);
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_async__execute_initiate_authentication_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    initiate_authentication_response_esipa_t request = { 0 };
    authenticate_client_request_esipa_t response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_initiate_authentication_response_esipa(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa_async__execute_initiate_authentication_response_esipa] Error parsing InitiateAuthenticationResponseEsipa message, rc %d", rc);
        return rc;
    }

    esipa_display__initiate_authentication_response_esipa(&request);

    /* Execute the use case in the IPA */
    if ((rc = ipa__initiate_authentication_response(&request, &response)) != eOk) {
        LOGE("[esipa_async__execute_initiate_authentication_response_esipa] Error executing the InitiateAuthenticationResponseEsipa against the IPA, rc %d", rc);
        return rc;
    }

    /* Send the response to the eIM */
    rc = esipa_async__send_authenticate_client_request_esipa(me, &response);
    ipa__free_authenticate_client_request_esipa(&response);
    if (rc != eOk) {
        LOGE("[esipa_async__execute_initiate_authentication_response_esipa] Error sending the AuthenticateClientRequestEsipa to the eIM, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_async__execute_authenticate_client_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size){
    ErrCode rc;
    authenticate_client_response_esipa_t request = { 0 };
    authenticate_client_response_result_esipa_t response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_authenticate_client_response_esipa(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa_async__execute_authenticate_client_response_esipa] Error parsing AuthenticateClientResponseEsipa message, rc %d", rc);
        return rc;
    }

    esipa_display__authenticate_client_response_esipa(&request);

    /* Execute the authenticate client response */
    if ((rc = ipa__authenticate_client_response(&request, &response)) != eOk) {
        LOGE("[esipa_async__execute_authenticate_client_response_esipa] Error executing the AuthenticateClientResponseEsipa against the IPA, rc %d", rc);
        return rc;
    }

    /* Send the response to the eIM */
    switch (response.choice) {
    case OK_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        rc = eOk;
        break;
    case CANCEL_SESSION_REQUEST_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        if ((rc = esipa_async__send_cancel_session_request_esipa(me, &response.value.cancel_session_request_esipa)) != eOk) {
            LOGE("[esipa_async__execute_authenticate_client_response_esipa] Error sending the CancelSessionRequestEsipa message to the eIM, rc %d", rc);
        }
        break;
    case PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE:
        if ((rc = esipa_async__send_profile_download_trigger_response_result(me, &response.value.profile_download_trigger_response_result)) != eOk) {
            LOGE("[esipa_async__execute_authenticate_client_response_esipa] Error sending the profile download result to the eIM, rc %d", rc);
        }
        break;
    case GET_BOUND_PROFILE_PACKAGE_AUTHENTICATE_CLIENT_RESULT_CHOICE:
        if ((rc = esipa_async__send_get_bound_profile_package_request_esipa(me, &response.value.get_bound_profile_package_request_esipa)) != eOk) {
            LOGE("[esipa_async__execute_authenticate_client_response_esipa] Error sending the GetBoundProfilePackageRequestEsipa message to the eIM, rc %d", rc);
        }
        break;
    default:
        LOGE("[esipa_async__execute_authenticate_client_response_esipa] Unknown result choice %d", response.choice);
        rc = eFatal;
        break;
    }

    ipa__free_authenticate_client_response_result_esipa(&response);

    return rc;
}

static ErrCode esipa_async__execute_get_bound_profile_package_response_esipa(esipa_async_t* const me, const uint8_t* message, const uint32_t message_size) {
    ErrCode rc;
    get_bound_profile_package_response_esipa_t request = { 0 };
    get_bound_profile_package_response_result_esipa_t response = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);

    /* Extract the data from the request */
    if ((rc = esipa_data_binding__extract_get_bound_profile_package_response_esipa(message, message_size, data_binding, &request)) != eOk) {
        LOGE("[esipa_async__execute_get_bound_profile_package_response_esipa] Error parsing GetBoundProfilePackageResponseEsipa message, rc %d", rc);
        return rc;
    }

    esipa_display__get_bound_profile_package_response_esipa(&request);

    /* Execute the get bound profile package*/
    if ((rc = ipa__get_bound_profile_package_response(&request, &response)) != eOk) {
        LOGE("[esipa_async__execute_get_bound_profile_package_response_esipa] Error executing the GetBoundProfilePackageResponseEsipa against the IPA, rc %d", rc);
        return rc;
    }

    /* Send the response to the eIM */
    switch (response.choice) {
    case CANCEL_SESSION_REQUEST_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
        if ((rc = esipa_async__send_cancel_session_request_esipa(me, &response.value.cancel_session_request_esipa)) != eOk) {
            LOGE("[esipa_async__execute_get_bound_profile_package_response_esipa] Error sending the cancelSessionRequestEsipa to the eIM, rc %d", rc);
        }
        break;
    case HANDLE_NOTIFICATION_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
        if ((rc = esipa_async__send_handle_notification_esipa(me, &response.value.handle_notification_esipa)) != eOk) {
            LOGE("[esipa_async__execute_get_bound_profile_package_response_esipa] Error sending the handleNotificationEsipa to the eIM, rc %d", rc);
        }
        break;
    default:
        LOGE("[esipa_async__execute_get_bound_profile_package_response_esipa] Unknown result choice %d", response.choice);
        rc = eFatal;
        break;
    }

    ipa__free_get_bound_profile_package_response_result_esipa(&response);

    return rc;
}
#endif

/* EsipaMessageFromIpaToEim */
static ErrCode esipa_async__send_get_eim_package_request(esipa_async_t * const me) {
    ErrCode rc;
    get_eim_package_request_t request = { 0 };
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    /* Populate the GetEimPackageRequest object */
    if ((rc = esipa__get_eim_package_request((esipa_t*) me, &request)) != eOk) {
        LOGE("[esipa_async__send_get_eim_package_request] Error populating the GetEimPackageRequest object, rc %d", rc);
        return rc;
    }

    esipa_display__get_eim_package_request(&request);

    /* Generate the GetEimPackageRequest message */
    if ((message_size = esipa_data_binding__generate_get_eim_package_request(NULL, 0, data_binding, &request)) < 0) {
        LOGE("[esipa_async__send_get_eim_package_request] Error calculating the size of the GetEimPackageRequest message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_get_eim_package_request] Can not allocate data to the GetEimPackageRequest message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_get_eim_package_request(message, message_size, data_binding, &request)) < 0) {
        LOGE("[esipa_async__send_get_eim_package_request] Error on generating the GetEimPackageRequest message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the GetEimPackageRequest message */
    LOG_DATA(eLogDebug, "[esipa_async__send_get_eim_package_request] GetEimPackageRequest", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_get_eim_package_request] Error sending the GetEimPackageRequest to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] GetEimPackageRequest sent to the eIM successfully");
        ipa__set_notify_state_change(NULL); /** TODO: Filter by eimId */
        esipa__set_last_message_sent((esipa_t*) me, GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_handle_notification_esipa(esipa_async_t * const me, const handle_notification_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_handle_notification_esipa] HandleNotificationEsipa object is null");
        return eBadArg;
    }
    esipa_display__handle_notification_esipa(in);

    /* Generate the HandleNotificationEsipa message */
    if ((message_size = esipa_data_binding__generate_handle_notification_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_handle_notification_esipa] Error calculating the size of the HandleNotificationEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_handle_notification_esipa] Can not allocate data to the HandleNotificationEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_handle_notification_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_handle_notification_esipa] Error on generating the HandleNotificationEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the HandleNotificationEsipa message */
    LOG_DATA(eLogDebug, "[esipa_async__send_handle_notification_esipa] HandleNotificationEsipa", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_handle_notification_esipa] Error sending the HandleNotificationEsipa to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] HandleNotificationEsipa sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, HANDLE_NOTIFICATION_ESIPA_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_transfer_eim_package_response(esipa_async_t * const me, const transfer_eim_package_response_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_transfer_eim_package_response] TransferEimPackageResponse object is null");
        return eBadArg;
    }
    esipa_display__transfer_eim_package_response(in);

    /* Generate the TransferEimPackageResponse message */
    if ((message_size = esipa_data_binding__generate_transfer_eim_package_response(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_transfer_eim_package_response] Error calculating the size of the TransferEimPackageResponse message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_transfer_eim_package_response] Can not allocate data to the TransferEimPackageResponse message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_transfer_eim_package_response(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_transfer_eim_package_response] Error on generating the TransferEimPackageResponse message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the TransferEimPackageResponse message */
    LOG_DATA(eLogDebug, "[esipa_async__send_transfer_eim_package_response] TransferEimPackageResponse", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_transfer_eim_package_response] Error sending the TransferEimPackageResponse to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] TransferEimPackageResponse sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_provide_eim_package_result(esipa_async_t * const me, const provide_eim_package_result_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_provide_eim_package_result] ProvideEimPackageResult object is null");
        return eBadArg;
    }
    esipa_display__provide_eim_package_result(in);

    /* Generate the ProvideEimPackageResult message */
    if ((message_size = esipa_data_binding__generate_provide_eim_package_result(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_provide_eim_package_result] Error calculating the size of the ProvideEimPackageResult message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_provide_eim_package_result] Can not allocate data to the ProvideEimPackageResult message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_provide_eim_package_result(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_provide_eim_package_result] Error on generating the ProvideEimPackageResult message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the ProvideEimPackageResult message */
    LOG_DATA(eLogDebug, "[esipa_async__send_provide_eim_package_result] ProvideEimPackageResult", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_provide_eim_package_result] Error sending the ProvideEimPackageResult to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] ProvideEimPackageResult sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, PROVIDE_EIM_PACKAGE_RESULT_CHOICE_EMFI);
    }

    return rc;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_async__send_initiate_authentication_request_esipa(esipa_async_t * const me, const initiate_authentication_request_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_initiate_authentication_request_esipa] InitiateAuthenticationRequestEsipa object is null");
        return eBadArg;
    }
    esipa_display__initiate_authentication_request_esipa(in);

    /* Generate the InitiateAuthenticationRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_initiate_authentication_request(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_initiate_authentication_request_esipa] Error calculating the size of the InitiateAuthenticationRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_initiate_authentication_request_esipa] Can not allocate data to the InitiateAuthenticationRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_initiate_authentication_request(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_initiate_authentication_request_esipa] Error on generating the InitiateAuthenticationRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the InitiateAuthenticationRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_async__send_initiate_authentication_request_esipa] InitiateAuthenticationRequestEsipa", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_initiate_authentication_request_esipa] Error sending the InitiateAuthenticationRequestEsipa to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] InitiateAuthenticationRequestEsipa sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_authenticate_client_request_esipa(esipa_async_t * const me, const authenticate_client_request_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_authenticate_client_request_esipa] AuthenticateClientRequestEsipa object is null");
        return eBadArg;
    }
    esipa_display__authenticate_client_request_esipa(in);

    /* Generate the AuthenticateClientRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_authenticate_client_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_authenticate_client_request_esipa] Error calculating the size of the AuthenticateClientRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_authenticate_client_request_esipa] Can not allocate data to the AuthenticateClientRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_authenticate_client_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_authenticate_client_request_esipa] Error on generating the AuthenticateClientRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the AuthenticateClientRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_async__send_authenticate_client_request_esipa] AuthenticateClientRequestEsipa", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_authenticate_client_request_esipa] Error sending the AuthenticateClientRequestEsipa to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] AuthenticateClientRequestEsipa sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, AUTHENTICATE_CLIENT_REQUEST_ESIPA_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_get_bound_profile_package_request_esipa(esipa_async_t* const me, const get_bound_profile_package_request_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_get_bound_profile_package_request_esipa] GetBoundProfilePackageRequestEsipa object is null");
        return eBadArg;
    }
    esipa_display__get_bound_profile_package_request_esipa(in);

    /* Generate the GetBoundProfilePackageRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_get_bound_profile_package_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_get_bound_profile_package_request_esipa] Error calculating the size of the GetBoundProfilePackageRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_get_bound_profile_package_request_esipa] Can not allocate data to the GetBoundProfilePackageRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_get_bound_profile_package_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_get_bound_profile_package_request_esipa] Error on generating the GetBoundProfilePackageRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the GetBoundProfilePackageRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_async__send_get_bound_profile_package_request_esipa] GetBoundProfilePackageRequestEsipa", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_get_bound_profile_package_request_esipa] Error sending the GetBoundProfilePackageRequestEsipa to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] GetBoundProfilePackageRequestEsipa sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, GET_BOUND_PROFILE_PACKAGE_REQUEST_ESIPA_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_cancel_session_request_esipa(esipa_async_t * const me, const cancel_session_request_esipa_t* in) {
    ErrCode rc;
    gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    uint8_t* message;
    uint32_t message_size;

    if (!in) {
        LOGE("[esipa_async__send_cancel_session_request_esipa] CancelSessionRequestEsipa object is null");
        return eBadArg;
    }
    esipa_display__cancel_session_request_esipa(in);

    /* Generate the CancelSessionRequestEsipa message */
    if ((message_size = esipa_data_binding__generate_cancel_session_request_esipa(NULL, 0, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_cancel_session_request_esipa] Error calculating the size of the CancelSessionRequestEsipa message, err %ld", message_size);
        return eFatal;
    }

    message = M_malloc(message_size);
    if (!message) {
        LOGE("[esipa_async__send_cancel_session_request_esipa] Can not allocate data to the CancelSessionRequestEsipa message");
        return eNoMem;
    }

    if ((message_size = esipa_data_binding__generate_cancel_session_request_esipa(message, message_size, data_binding, in)) < 0) {
        LOGE("[esipa_async__send_cancel_session_request_esipa] Error on generating the CancelSessionRequestEsipa message, err %ld", message_size);
        M_free(message);
        return eFatal;
    }

    /* Send the CancelSessionRequestEsipa message */
    LOG_DATA(eLogDebug, "[esipa_async__send_cancel_session_request_esipa] CancelSessionRequestEsipa", message, message_size);
    if ((rc = esipa_async__send_message(me, &message, (uint32_t*) &message_size)) != eOk) {
        LOGE("[esipa_async__send_cancel_session_request_esipa] Error sending the CancelSessionRequestEsipa to the eIM, rc %d", rc);
    } else {
        LOGI("[ESipa] CancelSessionRequestEsipa sent to the eIM successfully");
        esipa__set_last_message_sent((esipa_t*) me, CANCEL_SESSION_REQUEST_ESIPA_CHOICE_EMFI);
    }

    return rc;
}

static ErrCode esipa_async__send_profile_download_trigger_result_indirect_notification(esipa_async_t * const me, const profile_download_trigger_result_t* in) {
    handle_notification_esipa_t handle_notification_esipa = {0};
    handle_notification_esipa.choice = PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE;

    if (!in) {
        LOGE("[esipa_async__send_profile_download_trigger_result_indirect_notification] The profile download object is null");
        return eBadArg;
    }
    /* Set the EID */
    ipa__get_eid(&handle_notification_esipa.value.provide_eim_package_result.eid_value);
    handle_notification_esipa.value.provide_eim_package_result.field_is_present.eid_value = true;

    handle_notification_esipa.value.provide_eim_package_result.eim_package_result.choice = PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR;
    memcpy(&handle_notification_esipa.value.provide_eim_package_result.eim_package_result.value.profile_download_trigger_result, in, sizeof(profile_download_trigger_result_t));

    /* Send the notification */
    return esipa_async__send_handle_notification_esipa(me, &handle_notification_esipa);
}

static ErrCode esipa_async__send_profile_download_trigger_response_result(esipa_async_t * const me, const profile_download_trigger_response_result_t* in) {
    ErrCode rc;

    if (!in) {
        LOGE("[esipa_async__send_profile_download_trigger_response_result] The paramater profile_download_trigger_response_result is null");
        return eBadArg;
    }

    switch (in->choice) {
    case PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE:
        rc = esipa_async__send_profile_download_trigger_result_indirect_notification(me, &in->value.profile_download_trigger_result);
        break;
    case INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE:
        /* Send the InitiateAuthenticationRequestEsipa */
        rc = esipa_async__send_initiate_authentication_request_esipa(me, &in->value.initiate_authentication_request_esipa);
        break;
    default:
        LOGE("[esipa_async__send_profile_download_trigger_response_result] Unknown CHOICE %d", in->choice);
        return eFatal;
    }
    return rc;
}
#endif

/* purely-virtual functions should never be called */
static ErrCode esipa_async__connect_default(esipa_async_t* const me) {
    return eNotImpl;
}

static ErrCode esipa_async__disconnect_default(esipa_async_t* const me) {
    return eNotImpl;
}

static bool esipa_async__keep_alive_default(esipa_async_t* const me) {
    return false;
}

static ErrCode esipa_async__send_message_default(esipa_async_t* const me, uint8_t** message, uint32_t* message_size) {
    return eNotImpl;
}
#endif
