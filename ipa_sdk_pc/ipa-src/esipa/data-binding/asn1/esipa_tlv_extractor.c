/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa_tlv_extractor.h"

#include "log.h"
#include "tlv_data_extractor.h"
#include "tlv_tags.h"
#include "tlv_lengths.h"
#include "ber_tlv_parser.h"
#include "es10_tlv_extractor.h"
#include "byte_utils.h"
#include "memory_manager.h"

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_tlv_extractor__initiate_authentication_ok_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_ok_esipa_t* initiate_authentication_ok_esipa);
static ErrCode esipa_tlv_extractor__initiate_authentication_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_error_esipa_t* error);
static ErrCode esipa_tlv_extractor__authenticate_client_ok_dp_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_ok_dp_esipa_t* authenticate_client_ok_dp_esipa);
static ErrCode esipa_tlv_extractor__authenticate_client_ok_ds_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_ok_ds_esipa_t* authenticate_client_ok_ds_esipa);
static ErrCode esipa_tlv_extractor__authenticate_client_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_error_esipa_t* error);
static ErrCode esipa_tlv_extractor__get_bound_profile_package_ok_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_ok_esipa_t* get_bound_profile_package_ok_esipa);
static ErrCode esipa_tlv_extractor__get_bound_profile_package_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_error_esipa_t* error);
static ErrCode esipa_tlv_extractor__cancel_session_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, cancel_session_error_esipa_t* error);
#endif
static ErrCode esipa_tlv_extractor__euicc_package_signed(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_signed_t* obj);
static ErrCode esipa_tlv_extractor__euicc_package(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_t* obj);
static ErrCode esipa_tlv_extractor__eim_package_error(const uint8_t* buffer, const uint32_t buffer_size, eim_package_error_from_eim_to_ipa_t* error);
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
static ErrCode esipa_tlv_extractor__profile_download_data(const uint8_t* buffer, const uint32_t buffer_size, const unsigned short tag, profile_download_data_t* profile_download_data);
#endif
static ErrCode esipa_tlv_extractor__euicc_package_signed(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_signed_t* obj);
static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_tag_list(const uint8_t* buffer, const uint32_t buffer_size, ipa_euicc_data_request_tag_list_t* tag_list);
static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, search_criteria_notification_t* obj);
static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, search_criteria_euicc_package_result_t* obj);
static ErrCode esipa_tlv_extractor__empty_response(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size);
static ErrCode esipa_tlv_extractor__provide_eim_package_result_error(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, provide_eim_package_result_error_t* error);
static inline ErrCode esipa_tlv_extractor__subject_key_identifier_possibly_truncated(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, subject_key_identifier_possibly_truncated_t* obj);

ErrCode esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice(const uint8_t* buffer, const uint32_t buffer_size, esipa_message_from_eim_to_ipa_choice_t* choice) {
    ErrCode rc;
    unsigned short tag;
    uint8_t tag_size;

    if (!choice) {
        LOGE("[esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice] The choice pointer is null");
        return eBadArg;
    }

    if ((rc = ber_tlv_parser__get_tag_data(buffer, buffer_size, 0, &tag, &tag_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice] Error reading the EsipaMessageFromEimToIpa TAG, rc %d", rc);
        return rc;
    }

    switch (tag)
    {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    case INITIATE_AUTHENTICATION:
        *choice = INITIATE_AUTHENTICATION_RESPONSE_ESIPA_CHOICE;
        break;
    case AUTHENTICATE_CLIENT:
        *choice = AUTHENTICATE_CLIENT_RESPONSE_ESIPA_CHOICE;
        break;
    case GET_BOUND_PROFILE_PACKAGE:
        *choice = GET_BOUND_PROFILE_PACKAGE_RESPONSE_ESIPA_CHOICE;
        break;
    case CANCEL_SESSION:
        *choice = CANCEL_SESSION_RESPONSE_ESIPA_CHOICE;
        break;
#endif
    case TRANSFER_EIM_PACKAGE:
        *choice = TRANSFER_EIM_PACKAGE_REQUEST_CHOICE;
        break;
    case GET_EIM_PACKAGE:
        *choice = GET_EIM_PACKAGE_RESPONSE_CHOICE;
        break;
    case PROVIDE_EIM_PACKAGE_RESULT:
        *choice = PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE;
        break;
    default:
        LOGE("[esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice] Unknown EsipaMessageFromEimToIpa TAG %04X", tag);
        return eFatal;
    }

    return eOk;
}

ErrCode esipa_tlv_extractor__transfer_eim_package_request(const uint8_t* buffer, const uint32_t buffer_size, transfer_eim_package_request_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__transfer_eim_package_request] TransferEimPackageRequest object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(TRANSFER_EIM_PACKAGE, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__transfer_eim_package_request] Error extracting the TransferEimPackageRequest child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case EUICC_PACKAGE:
        LOGD("[esipa_tlv_extractor__transfer_eim_package_request] The TransferEimPackageRequest is a EuiccPackageRequest");
        obj->choice = EUICC_PACKAGE_REQUEST_CHOICE_TEPR;
        
        if (!child_tlv || child_tlv_size == 0) {
            LOGE("[esipa_tlv_extractor__transfer_eim_package_request] Child TLV is null or empty");
            return eBadArg;
        }
        
        /* Store reference to buffer - no allocation needed.
         * The caller must keep the source buffer valid while using this structure. */
        obj->value.euicc_package_request.euicc_package_request = child_tlv;
        obj->value.euicc_package_request.euicc_package_request_size = child_tlv_size;
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__transfer_eim_package_request] EuiccPackageRequest reference", obj->value.euicc_package_request.euicc_package_request, obj->value.euicc_package_request.euicc_package_request_size);
        return eOk;
    case IPA_EUICC_DATA:
        LOGD("[esipa_tlv_extractor__transfer_eim_package_request] The TransferEimPackageRequest is a IpaEuiccDataRequest");
        obj->choice = IPA_EUICC_DATA_REQUEST_CHOICE_TEPR;
        rc = esipa_tlv_extractor__ipa_euicc_data_request(child_tlv, child_tlv_size, &obj->value.ipa_euicc_data_request);
        break;
    case EIM_ACKNOWLEDGEMENTS:
        LOGD("[esipa_tlv_extractor__transfer_eim_package_request] The TransferEimPackageRequest is a EimAcknowledgements");
        obj->choice = EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR;
        rc = esipa_tlv_extractor__eim_acknowledgements(child_tlv, child_tlv_size, &obj->value.eim_acknowledgements);
        break;
    case PROFILE_DOWNLOAD_TRIGGER:
        LOGD("[esipa_tlv_extractor__transfer_eim_package_request] The TransferEimPackageRequest is a ProfileDownloadTriggerRequest");
        obj->choice = PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR;
        rc = esipa_tlv_extractor__profile_download_trigger_request(child_tlv, child_tlv_size, &obj->value.profile_download_trigger_request);
        break;
    default:
        LOGE("[esipa_tlv_extractor__transfer_eim_package_request] Unknown TransferEimPackageRequest CHOICE, tag %04X", child_tag);
        return eNotSupported;
    }

    if (rc != eOk) {
        LOGE("[esipa_tlv_extractor__transfer_eim_package_request] Error on parse the TLV for the %d choice, err %d", obj->choice, rc);
        return eInvalidFormat;
    }

    return eOk;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
ErrCode esipa_tlv_extractor__initiate_authentication_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_response_esipa_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_response_esipa] InitiateAuthenticationResponseEsipa object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(INITIATE_AUTHENTICATION, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_response_esipa] Error extracting the InitiateAuthenticationResponseEsipa child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case INITIATE_AUTHENTICATION_OK_ESIPA:
        LOGD("[esipa_tlv_extractor__initiate_authentication_response_esipa] The InitiateAuthenticationResponseEsipa is a initiateAuthenticationOkEsipa");
        obj->choice = INITIATE_AUTHENTICATION_OK_ESIPA_CHOICE;
        return esipa_tlv_extractor__initiate_authentication_ok_esipa(child_tlv, child_tlv_size, &obj->value.initiate_authentication_ok_esipa);
    case INITIATE_AUTHENTICATION_ERROR_ESIPA:
        LOGD("[esipa_tlv_extractor__initiate_authentication_response_esipa] The InitiateAuthenticationResponseEsipa is a initiateAuthenticationErrorEsipa");
        obj->choice = INITIATE_AUTHENTICATION_ERROR_ESIPA_CHOICE;
        return esipa_tlv_extractor__initiate_authentication_error_esipa(child_tlv, child_tlv_size, &obj->value.initiate_authentication_error_esipa);
    default:
        LOGE("[esipa_tlv_extractor__initiate_authentication_response_esipa] Unknown InitiateAuthenticationResponseEsipa CHOICE, tag %04X", child_tag);
        return eFatal;
    }    
}

ErrCode esipa_tlv_extractor__authenticate_client_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_response_esipa_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__authenticate_client_response_esipa] AuthenticateClientResponseEsipa object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(AUTHENTICATE_CLIENT, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_response_esipa] Error extracting the AuthenticateClientResponseEsipa child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag) {
    case AUTHENTICATE_CLIENT_OK_DP_ESIPA:
        LOGD("[esipa_tlv_extractor__authenticate_client_response_esipa] The AuthenticateClientResponseEsipa is a authenticateClientOkDpEsipa");
        obj->choice = AUTHENTICATE_CLIENT_OK_DP_ESIPA_CHOICE;
        return esipa_tlv_extractor__authenticate_client_ok_dp_esipa(child_tlv, child_tlv_size, &obj->value.authenticate_client_ok_dp_esipa);
    case AUTHENTICATE_CLIENT_OK_DS_ESIPA:
        LOGD("[esipa_tlv_extractor__authenticate_client_response_esipa] The AuthenticateClientResponseEsipa is a authenticateClientOkDsEsipa");
        obj->choice = AUTHENTICATE_CLIENT_OK_DS_ESIPA_CHOICE;
        return esipa_tlv_extractor__authenticate_client_ok_ds_esipa(child_tlv, child_tlv_size, &obj->value.authenticate_client_ok_ds_esipa);
    case AUTHENTICATE_CLIENT_ERROR_ESIPA:
        LOGD("[esipa_tlv_extractor__authenticate_client_response_esipa] The AuthenticateClientResponseEsipa is a authenticateClientErrorEsipa");
        obj->choice = AUTHENTICATE_CLIENT_ERROR_ESIPA_CHOICE;
        return esipa_tlv_extractor__authenticate_client_error_esipa(child_tlv, child_tlv_size, &obj->value.authenticate_client_error_esipa);
    default:
        LOGE("[esipa_tlv_extractor__authenticate_client_response_esipa] Unknown AuthenticateClientResponseEsipa CHOICE, tag %04X", child_tag);
        return eFatal;
    } 
}

ErrCode esipa_tlv_extractor__get_bound_profile_package_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_response_esipa_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_response_esipa] GetBoundProfilePackageResponseEsipa object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(GET_BOUND_PROFILE_PACKAGE, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_response_esipa] Error extracting the GetBoundProfilePackageResponseEsipa child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag) {
    case GET_BOUND_PROFILE_PACKAGE_OK_ESIPA:
        LOGD("[esipa_tlv_extractor__get_bound_profile_package_response_esipa] The GetBoundProfilePackageResponseEsipa is a getBoundProfilePackageOkEsipa");
        obj->choice = GET_BOUND_PROFILE_PACKAGE_OK_ESIPA_CHOICE;
        return esipa_tlv_extractor__get_bound_profile_package_ok_esipa(child_tlv, child_tlv_size, &obj->value.get_bound_profile_package_ok_esipa);
    case GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA:
        LOGD("[esipa_tlv_extractor__get_bound_profile_package_response_esipa] The GetBoundProfilePackageResponseEsipa is a getBoundProfilePackageErrorEsipa");
        obj->choice = GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA_CHOICE;
        return esipa_tlv_extractor__get_bound_profile_package_error_esipa(child_tlv, child_tlv_size, &obj->value.get_bound_profile_package_error_esipa);
    default:
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_response_esipa] Unknown GetBoundProfilePackageResponseEsipa CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

ErrCode esipa_tlv_extractor__cancel_session_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, cancel_session_response_esipa_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__cancel_session_response_esipa] CancelSessionResponseEsipa object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(CANCEL_SESSION, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__cancel_session_response_esipa] Error extracting the CancelSessionResponseEsipa child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        LOGD("[esipa_tlv_extractor__cancel_session_response_esipa] The CancelSessionResponseEsipa is a cancelSessionOk");
        obj->choice = CANCEL_SESSION_OK_ESIPA;
        return eOk;
    case CONTEXT_PRIMITIVE_1:
        LOGD("[esipa_tlv_extractor__cancel_session_response_esipa] The CancelSessionResponseEsipa is a cancelSessionError");
        obj->choice = CANCEL_SESSION_ERROR_ESIPA;
        return esipa_tlv_extractor__cancel_session_error_esipa(child_tlv, child_tlv_size, &obj->cancel_session_error);
    default:
        LOGE("[esipa_tlv_extractor__cancel_session_response_esipa] Unknown CancelSessionResponseEsipa CHOICE, tag %02X", child_tag);
        return eFatal;
    }
}

#if defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && defined(IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION)
ErrCode esipa_tlv_extractor__matching_id_is_present_ctx_params1_value(const uint8_t* tlv, const uint16_t tlv_size, bool* matchind_id_is_present) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint16_t tlv_value_size;
    uint8_t* sub_tlv_value;
    uint16_t sub_tlv_value_size;

    /* Check input parameters */
    if (!tlv || 0 == tlv_size) {
        LOGE("[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] tlv is empty/null");
        return eBadArg;
    }
    if (!matchind_id_is_present) {
        LOGE("[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] matchind_id_is_present pointer is null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] CtxParamsForCommonAuthentication TLV", tlv, (size_t) tlv_size);

    //Search the CtxParamsForCommonAuthentication  TLV
    if ((rc = tlv_data_extractor__tlv_value_medium_size_ref(CONTEXT_CONSTRUCTED_0,  tlv, (uint32_t) tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] Error extracting the CtxParamsForCommonAuthentication, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] CtxParamsForCommonAuthentication TLV VALUE", tlv_value, (size_t) tlv_value_size);

    //Search if matchingId is present
    if ((rc = tlv_data_extractor__tlv_value_medium_size_ref(CTX_PARAMS_1_MATCHING_ID, tlv_value, (uint32_t) tlv_value_size, matchind_id_is_present, &sub_tlv_value, &sub_tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] Error extracting the matchingId, rc %d", rc);
        return rc;
    }

    if (*matchind_id_is_present && sub_tlv_value != NULL && sub_tlv_value_size > 0)  {
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] matchingId", sub_tlv_value, (size_t) sub_tlv_value_size);
    } else {
        LOGD("[esipa_tlv_extractor__matching_id_is_present_ctx_params1_value] matchingId is not present");
        *matchind_id_is_present = false;
    }

    return rc;
}
#endif
#endif

ErrCode esipa_tlv_extractor__get_eim_package_response(const uint8_t* buffer, const uint32_t buffer_size, get_eim_package_response_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__get_eim_package_response] GetEimPackageResponse object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(GET_EIM_PACKAGE, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__get_eim_package_response] Error extracting the GetEimPackageResponse child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case EUICC_PACKAGE:
        LOGD("[esipa_tlv_extractor__get_eim_package_response] The GetEimPackageResponse is a EuiccPackageRequest");
        obj->choice = EUICC_PACKAGE_REQUEST_CHOICE_GEPR;
        
        if (!child_tlv || child_tlv_size == 0) {
            LOGE("[esipa_tlv_extractor__get_eim_package_response] Child TLV is null or empty");
            return eBadArg;
        }
        
        /* Store reference to buffer - no allocation needed.
         * The caller must keep the source buffer valid while using this structure. */
        obj->value.euicc_package_request.euicc_package_request = child_tlv;
        obj->value.euicc_package_request.euicc_package_request_size = child_tlv_size;
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__get_eim_package_response] EuiccPackageRequest reference", obj->value.euicc_package_request.euicc_package_request, obj->value.euicc_package_request.euicc_package_request_size);
        return eOk;
    case IPA_EUICC_DATA:
        LOGD("[esipa_tlv_extractor__get_eim_package_response] The GetEimPackageResponse is a IpaEuiccDataRequest");
        obj->choice = IPA_EUICC_DATA_REQUEST_CHOICE_GEPR;
        return esipa_tlv_extractor__ipa_euicc_data_request(child_tlv, child_tlv_size, &obj->value.ipa_euicc_data_request);
    case PROFILE_DOWNLOAD_TRIGGER:
        LOGD("[esipa_tlv_extractor__get_eim_package_response] The GetEimPackageResponse is a ProfileDownloadTriggerRequest");
        obj->choice = PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR;
        return esipa_tlv_extractor__profile_download_trigger_request(child_tlv, child_tlv_size, &obj->value.profile_download_trigger_request);
    case ASN1_DER_INTEGER:
        LOGD("[esipa_tlv_extractor__get_eim_package_response] The GetEimPackageResponse is a eimPackageError");
        obj->choice = EIM_PACKAGE_ERROR_CHOICE_GEPR;
        return esipa_tlv_extractor__eim_package_error(child_tlv, child_tlv_size, &obj->value.eim_package_error);
    default:
        LOGE("[esipa_tlv_extractor__get_eim_package_response] Unknown GetEimPackageResponse CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

ErrCode esipa_tlv_extractor__provide_eim_package_result_response(const uint8_t* buffer, const uint32_t buffer_size, provide_eim_package_result_response_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_response] ProvideEimPackageResultResponse object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(PROVIDE_EIM_PACKAGE_RESULT, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_response] Error extracting the ProvideEimPackageResultResponse child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case EIM_ACKNOWLEDGEMENTS:
        LOGD("[esipa_tlv_extractor__provide_eim_package_result_response] The ProvideEimPackageResultResponse is an eimAcknowledgements");
        obj->choice = EIM_ACKNOWLEDGEMENTS_CHOICE_PEPRR;
        return esipa_tlv_extractor__eim_acknowledgements(child_tlv, child_tlv_size, &obj->value.eim_acknowledgements);
    case ASN1_DER_SEQUENCE:
        LOGD("[esipa_tlv_extractor__provide_eim_package_result_response] The ProvideEimPackageResultResponse is an emptyResponse");
        obj->choice = EMPTY_RESPONSE_CHOICE_PEPRR;
        return esipa_tlv_extractor__empty_response(ASN1_DER_SEQUENCE, child_tlv, child_tlv_size);
    case ASN1_DER_INTEGER:
        LOGD("[esipa_tlv_extractor__provide_eim_package_result_response] The ProvideEimPackageResultResponse is a provideEimPackageResultError");
        obj->choice = PROVIDE_EIM_PACKAGE_RESULT_ERROR_CHOICE_PEPRR;
        return esipa_tlv_extractor__provide_eim_package_result_error(ASN1_DER_INTEGER, child_tlv, child_tlv_size, &obj->value.provide_eim_package_result_error);
    default:
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_response] Unknown ProvideEimPackageResultResponse CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

ErrCode esipa_tlv_extractor__euicc_package_request(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_request_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__euicc_package_request] EuiccPackageRequest object is null");
        return eBadArg;
    }

    // Get EuiccPackageRequest value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(EUICC_PACKAGE, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request] Error extracting the EuiccPackageRequest TLV value");
        return rc;
    }

    // Parse euiccPackageSigned
    if ((rc = esipa_tlv_extractor__euicc_package_signed(tlv_value, tlv_value_size, &obj->euicc_package_signed)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request] Error parsing the euiccPackageSigned, rc %d", rc);
        return rc;
    }

    // Parse eimSignature
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(SIGNATURE, tlv_value, tlv_value_size, NULL, &obj->eim_signature, &obj->eim_signature_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request] Error extracting the eimSignature, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request] eimSignature", obj->eim_signature, obj->eim_signature_size);

    return eOk;
}

#ifdef SGP22
/** This function extracts data from a EuiccPackageRequest TLV.
 *
 * @param[in]  euicc_package_req Pointer to a buffer with the EuiccPackageRequest TLV.
 * @param[in]  euicc_package_req_size Size of the euicc_package_req buffer.
 * @param[out] eim_id_tlv_offset The value will be the offset where the eimId TLV is located regarding the euicc_package_req buffer in case that the function has been successfully executed.
 * @param[out] eim_id_tlv_size Size of the located eimId TLV in case that the function has been successfully executed.
 * @param[out] counter_value_tlv_offset The value will be the offset where the counterValue TLV is located regarding the euicc_package_req buffer in case that the function has been successfully executed.
 * @param[out] counter_value_tlv_size Size of the located counterValue TLV in case that the function has been successfully executed.
 * @param[out] transaction_id_tlv_offset The value will be the offset where the transactionId TLV is located regarding the euicc_package_req buffer in case that the function has been successfully executed.
 * If no transactionId TLV is found, the value will be 0.
 * @param[out] transaction_id_tlv_size Size of the located transactionId TLV in case that the function has been successfully executed. If no transactionId TLV is found, the value will be 0.
 * @param[out] psmo_tlv_offset The value will be the offset where the Psmo TLV is located regarding the euicc_package_req buffer in case that the function has been successfully executed.
 * @param[out] psmo_tlv_size Size of the located Psmo TLV in case that the function has been successfully executed.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__euicc_package_request_plain_data(const uint8_t* euicc_package_req, const size_t euicc_package_req_size,
    size_t* eim_id_tlv_offset, uint8_t* eim_id_tlv_size, size_t* counter_value_tlv_offset, size_t* counter_value_tlv_size, 
    size_t*  transaction_id_tlv_offset, uint8_t* transaction_id_tlv_size, size_t* psmo_tlv_offset, size_t* psmo_tlv_size) {
    
    ErrCode rc;
    int tlv_offset;
    int tlv_child_offset;
    size_t tlv_value_offset;
    size_t tlv_child_value_offset;
    _BerTlv tlv_child_obj;

    if (!euicc_package_req || euicc_package_req_size == 0) {
        return eBadArg;
    }

    //Search the EuiccPackageRequest TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, 0, EUICC_PACKAGE);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of EuiccPackageRequest (%04X) not found", EUICC_PACKAGE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(euicc_package_req, (size_t) tlv_offset);
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] EuiccPackageRequest value", euicc_package_req + tlv_value_offset, euicc_package_req_size - tlv_value_offset);

    //Search the EuiccPackageSigned TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, tlv_value_offset, ASN1_DER_SEQUENCE);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of EuiccPackageSigned (%04X) not found", ASN1_DER_SEQUENCE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(euicc_package_req, (size_t) tlv_offset);
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] EuiccPackageSigned value start", euicc_package_req + tlv_value_offset, euicc_package_req_size - tlv_value_offset);

    //Search the eimId
    tlv_child_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, tlv_value_offset, CONTEXT_PRIMITIVE_0);
    if (tlv_child_offset < 0) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of eimId (%04X) not found", CONTEXT_PRIMITIVE_0);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(euicc_package_req, euicc_package_req_size, (size_t) tlv_child_offset, &tlv_child_obj)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] Error parsing the eimId TLV from the EuiccPackageRequest TLV on offset %u, rc %d", (unsigned int) tlv_child_offset, rc);
        return eFatal;
    }
    if (EIM_ID_MAX_SIZE < tlv_child_obj.length) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] eimId TLV size %u is greater than the maximum size %u", tlv_child_obj.length, EIM_ID_MAX_SIZE);
        return eFatal;
    }
    *eim_id_tlv_offset = (size_t) tlv_child_offset;
    *eim_id_tlv_size =  (uint8_t) tlv_child_obj.nTag + (uint8_t) tlv_child_obj.nLength + (uint8_t) tlv_child_obj.length;
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] eimId", euicc_package_req + *eim_id_tlv_offset, *eim_id_tlv_size);

    //Search the counterValue
    tlv_child_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, tlv_value_offset, CONTEXT_PRIMITIVE_1);
    if (tlv_child_offset < 0) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of counterValue (%04X) not found", CONTEXT_PRIMITIVE_1);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(euicc_package_req, euicc_package_req_size, (size_t) tlv_child_offset, &tlv_child_obj)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] Error parsing the counterValue TLV from the EuiccPackageRequest TLV on offset %u, rc %d", (unsigned int) tlv_child_offset, rc);
        return eFatal;
    }
    *counter_value_tlv_offset = (size_t) tlv_child_offset;
    *counter_value_tlv_size = (uint8_t) tlv_child_obj.nTag + (uint8_t) tlv_child_obj.nLength + (uint8_t) tlv_child_obj.length;
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] counterValue", euicc_package_req + *counter_value_tlv_offset, *counter_value_tlv_size);

    //Search the transactionId
    tlv_child_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, tlv_value_offset, CONTEXT_PRIMITIVE_2);
    if (tlv_child_offset < 0) {
        LOGD("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of transactionId (%04X) not found", CONTEXT_PRIMITIVE_2);
        *transaction_id_tlv_offset = 0;
        *transaction_id_tlv_size = 0;
    } else {
        if ((rc = ber_tlv_parser__ber_tlv_2(euicc_package_req, euicc_package_req_size, (size_t) tlv_child_offset, &tlv_child_obj)) != eOk) {
            LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] Error parsing the transactionId TLV from the EuiccPackageRequest TLV on offset %u, rc %d", (unsigned int) tlv_child_offset, rc);
            return eFatal;
        }
        if (TRANSACION_ID_MAX_SIZE < tlv_child_obj.length) {
            LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] transactionId TLV size %u is greater than the maximum size %u", tlv_child_obj.length, TRANSACION_ID_MAX_SIZE);
            return eFatal;
        }
        *transaction_id_tlv_offset = (size_t) tlv_child_offset;
        *transaction_id_tlv_size = (uint8_t) tlv_child_obj.nTag + (uint8_t) tlv_child_obj.nLength + (uint8_t) tlv_child_obj.length;
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] transactionId", euicc_package_req + *transaction_id_tlv_offset, *transaction_id_tlv_size);
    }

    //Search the first Psmo of the psmoList
    tlv_child_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) euicc_package_req, euicc_package_req_size, tlv_value_offset, CONTEXT_CONSTRUCTED_0);
    if (tlv_child_offset < 0) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] TAG of first Psmo (%04X) not found", CONTEXT_CONSTRUCTED_0);
        return eFatal;
    }
    tlv_child_value_offset = ber_tlv_parser__get_value_offset(euicc_package_req, (size_t) tlv_child_offset);
    if ((rc = ber_tlv_parser__ber_tlv_2(euicc_package_req, euicc_package_req_size, tlv_child_value_offset, &tlv_child_obj)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_request_plain_data] Error parsing the first Psmo TLV of the psmoList TLV from the EuiccPackageRequest TLV on offset %u, rc %d", (unsigned int) tlv_child_value_offset, rc);
        return eFatal;
    }
    *psmo_tlv_offset = tlv_child_value_offset;
    *psmo_tlv_size = tlv_child_obj.nTag + tlv_child_obj.nLength + tlv_child_obj.length;
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_request_plain_data] Psmo", euicc_package_req + *psmo_tlv_offset, *psmo_tlv_size);

    return eOk;  
}

/** This function extracts the iccid from a Psmo TLV value where its CHOICE is enable, disable or delete.
 *
 * @param[in]  psmo Pointer to a Psmo TLV value where its CHOICE is enable, disable or delete.
 * @param[in]  psmo_size Size of the Psmo TLV value.
 * @param[out] iccid Pointer to a preallocated buffer of size 10 that will be filled with a copy of the iccid of the Psmo TLV value in case that the function has been successfully executed.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__iccid_value_from_psmo(const uint8_t* psmo, const size_t psmo_size, iccid_t* iccid) {
    ErrCode rc;
    int tlv_child_offset;
    _BerTlv psmo_tlv;
    _BerTlv iccid_tlv;

    if (!psmo || psmo_size == 0) {
        return eBadArg;
    }

    rc = ber_tlv_parser__ber_tlv_2(psmo, psmo_size, 0, &psmo_tlv);
    if (rc != eOk) {
        LOGE("[esipa_tlv_extractor__iccid_value_from_psmo] Error parsing the Psmo to TLV, rc %d", rc);
        return rc;
    }

    if (PSMO_ENABLE != psmo_tlv.tag && PSMO_DISABLE != psmo_tlv.tag && PSMO_DELETE != psmo_tlv.tag) {
        LOGE("[esipa_tlv_extractor__iccid_value_from_psmo] Invalid TAG %04X", psmo_tlv.tag);
        return eFatal;
    }

    tlv_child_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) psmo, psmo_size, psmo_tlv.nTag + psmo_tlv.nLength, ICCID);
    if (tlv_child_offset < 0) {
        LOGE("[esipa_tlv_extractor__iccid_value_from_psmo] TAG of iccid (%02X) not found", ICCID);
        return eFatal;
    }

    rc = ber_tlv_parser__ber_tlv_2(psmo, psmo_size, (size_t) tlv_child_offset, &iccid_tlv);
    if (rc != eOk) {
        LOGE("[esipa_tlv_extractor__iccid_value_from_psmo] Error parsing the Iccid to TLV, rc %d", rc);
        return rc;
    }
    if (sizeof(iccid->value) != iccid_tlv.length) {
        LOGE("[esipa_tlv_extractor__iccid_value_from_psmo] Invalid length of the iccid %u", iccid_tlv.length);
        return eFatal;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__iccid_value_from_psmo] ICCID", psmo + (size_t) tlv_child_offset + iccid_tlv.nTag + iccid_tlv.nLength, iccid_tlv.length);

    memcpy(iccid->value, psmo + (size_t) tlv_child_offset + iccid_tlv.nTag + iccid_tlv.nLength, sizeof(iccid->value));
    
    return eOk;
}
#endif

/** This function extracts data from a ipaEuiccDataRequest TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the ipaEuiccDataRequest TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] ipa_euicc_data_request A pointer to a ipa_euicc_data_request_t structure initialized with IPA_EUICC_DATA_REQUEST_INITIALIZER. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__ipa_euicc_data_request(const uint8_t* buffer, const uint32_t buffer_size, ipa_euicc_data_request_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    
    /* Check input parameters */
    if (!buffer || buffer_size == 0) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] ipaEuiccDataRequest TLV is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] ipaEuiccDataRequest object is null");
        return eBadArg;
    }

    // Get the ipaEuiccDataRequest VALUE
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(IPA_EUICC_DATA, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error on extract the value of the ipaEuiccDataRequest TLV, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__ipa_euicc_data_request] IpaEuiccDataRequest value", tlv_value, tlv_value_size);

    // tagList
    if ((rc = esipa_tlv_extractor__ipa_euicc_data_request_tag_list(tlv_value, tlv_value_size, &obj->tag_list)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error parsing the tagList data, rc %d", rc);
        return rc;
    }

    // euiccCiPKIdentifierToBeUsed OPTIONAL
    if ((rc = esipa_tlv_extractor__subject_key_identifier_possibly_truncated(ASN1_DER_OCTET_STRING, tlv_value, tlv_value_size, &obj->field_is_present.euicc_ci_pk_id, &obj->euicc_ci_pk_id_to_be_used)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error parsing the euiccCiPKIdentifierToBeUsed, rc %d", rc);
        return rc;
    }

    // searchCriteriaNotification OPTIONAL
    if ((rc = esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification(CONTEXT_CONSTRUCTED_1, tlv_value, tlv_value_size, &obj->field_is_present.search_criteria_notification, &obj->search_criteria_notification)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error parsing the searchCriteriaNotification, rc %d", rc);
        return rc;
    }

    // searchCriteriaEuiccPackageResult OPTIONAL
    if ((rc = esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result(CONTEXT_CONSTRUCTED_2, tlv_value, tlv_value_size, &obj->field_is_present.search_criteria_euicc_package_result, &obj->search_criteria_euicc_package_result)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error parsing the searchCriteriaEuiccPackageResult, rc %d", rc);
        return rc;
    }

    //Search the transactionId OPTIONAL
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_3, tlv_value, tlv_value_size, &obj->field_is_present.eim_transaction_id, &obj->eim_transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error extracting the eimTransactionId, rc %d", rc);
        return rc;
    }

    return eOk;
}

/** This function extracts data from a profileDownloadTriggerRequest TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the ipaEuiccDataRequest TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] profile_download_request A pointer to a profile_download_trigger_request_t structure initialized with PROFILE_DOWNLOAD_TRIGGER_REQUEST_INITIALIZER. The structure is populated following its 
 * documentation with the data from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__profile_download_trigger_request(const uint8_t* buffer, const uint32_t buffer_size, profile_download_trigger_request_t* profile_download_request) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv tlv_child_obj;

    if (!buffer || buffer_size == 0) {
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__profile_download_trigger_request] profileDownloadTriggerRequest TLV", buffer, buffer_size);

    //Search the profileDownloadTriggerRequest TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) buffer, buffer_size, 0, PROFILE_DOWNLOAD_TRIGGER);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__profile_download_trigger_request] TAG of profileDownloadTriggerRequest (%04X) not found", PROFILE_DOWNLOAD_TRIGGER);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__profile_download_trigger_request] profileDownloadTriggerRequest value", buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset);

    //Search the eimTransactionId TLV [OPTIONAL]
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) buffer, buffer_size, tlv_value_offset, PROFILE_DOWNLOAD_TRIGGER_EIM_TRANSACTION_ID);
    if (tlv_offset < 0) {
        LOGD("[esipa_tlv_extractor__profile_download_trigger_request] TAG of eimTransactionId (%02X) not found, optional field", PROFILE_DOWNLOAD_TRIGGER_EIM_TRANSACTION_ID);
        profile_download_request->field_is_present.eim_transaction_id = false;
    } else {
        if ((rc = ber_tlv_parser__ber_tlv_2(buffer, buffer_size, (size_t) tlv_offset, &tlv_child_obj)) != eOk) {
            LOGE("[tlv_data_extractor__euicc_package_request] Error parsing the eimTransactionId TLV from the profileDownloadTriggerRequest TLV on offset %u, rc %d", (unsigned int) tlv_offset, rc);
            return eFatal;
        }
        LOG_DATA(eLogTrace, "[esipa_tlv_extractor__profile_download_trigger_request] eimTransactionId TLV", buffer + tlv_offset, tlv_child_obj.nTag + tlv_child_obj.nLength + tlv_child_obj.length);
        if (TRANSACION_ID_MAX_SIZE < tlv_child_obj.length) {
            LOGE("[esipa_tlv_extractor__profile_download_trigger_request] eimTransactionId TLV size %u is greater than the maximum size %u", tlv_child_obj.length, TRANSACION_ID_MAX_SIZE);
            return eFatal;
        }
        memcpy(profile_download_request->eim_transaction_id.transaction_id, buffer + tlv_offset + tlv_child_obj.nTag + tlv_child_obj.nLength, tlv_child_obj.length);
        profile_download_request->eim_transaction_id.transaction_id_size = (uint8_t) tlv_child_obj.length;
        profile_download_request->field_is_present.eim_transaction_id = true;
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__profile_download_trigger_request] eimTransactionId", profile_download_request->eim_transaction_id.transaction_id, profile_download_request->eim_transaction_id.transaction_id_size);
    }

#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
    //Search the profileDownloadData TLV
    return esipa_tlv_extractor__profile_download_data(buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, PROFILE_DOWNLOAD_DATA, &profile_download_request->profile_download_data);
#else
    return eOk;
#endif
}

ErrCode esipa_tlv_extractor__eim_acknowledgements(const uint8_t* buffer, const uint32_t buffer_size, eim_acknowledgements_t* eim_acknowlegdements) {
    return tlv_data_extractor__asn1_list_init(&eim_acknowlegdements->sequence_number_list, EIM_ACKNOWLEDGEMENTS, CONTEXT_PRIMITIVE_0, buffer, buffer_size);
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/** This function extracts data from a InitiateAuthenticationOkEsipa  TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the InitiateAuthenticationOkEsipa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] initiate_authentication_ok_esipa A pointer to a initiate_authentication_ok_esipa_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
static ErrCode esipa_tlv_extractor__initiate_authentication_ok_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_ok_esipa_t* initiate_authentication_ok_esipa) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    
    if (!buffer || buffer_size == 0) {
        return eBadArg;
    }

    //Search the InitiateAuthenticationOkEsipa TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, INITIATE_AUTHENTICATION_OK_ESIPA);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] TAG of InitiateAuthenticationOkEsipa (%04X) not found", INITIATE_AUTHENTICATION_OK_ESIPA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] InitiateAuthenticationOkEsipa value", buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset);

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    //euiccCiPKIdToBeUsed truncated
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(EUICC_CI_PK_ID, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL,
        initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, sizeof(initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.value), &initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the truncated euiccCiPKIdToBeUsed, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] truncated euiccCiPKIdToBeUsed", initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.size);
#else
    //euiccCiPKIdToBeUsed  
    if ((rc = tlv_data_extractor__subject_key_identifier(EUICC_CI_PK_ID, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the euiccCiPKIdToBeUsed, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] euiccCiPKIdToBeUsed", initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, sizeof(initiate_authentication_ok_esipa->euicc_ci_pk_id_to_be_used.subject_key_identifier.value));

    //Search the transactionId [OPTIONAL]
    if ((rc = tlv_data_extractor__transaction_id(INITIATE_AUTHENTICATION_OK_ESIPA_TRANSACTION_ID,
                                                buffer + tlv_value_offset,
                                                buffer_size - (uint32_t) tlv_value_offset,
                                                &initiate_authentication_ok_esipa->field_is_present.transaction_id,
                                                &initiate_authentication_ok_esipa->transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the transactionId, rc %d", rc);
        return rc;
    }
#endif

    //Search the serverSigned1 TLV
    if ((rc = tlv_data_extractor__tlv_big_size_ref(ASN1_DER_SEQUENCE,  buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &initiate_authentication_ok_esipa->server_signed_1, &initiate_authentication_ok_esipa->server_signed_1_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the serverSigned1, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] serverSigned1 TLV", initiate_authentication_ok_esipa->server_signed_1, (size_t) initiate_authentication_ok_esipa->server_signed_1_size);

    //Search the serverSignature1 TLV
    if ((rc = tlv_data_extractor__tlv_small_size_ref(SIGNATURE, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &initiate_authentication_ok_esipa->server_signature_1, &initiate_authentication_ok_esipa->server_signature_1_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the serverSignature1, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] serverSignature1 TLV", initiate_authentication_ok_esipa->server_signature_1, (size_t) initiate_authentication_ok_esipa->server_signature_1_size);

    if (initiate_authentication_ok_esipa->server_signed_1 > initiate_authentication_ok_esipa->server_signature_1) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] serverSigned1 found after serverSignature1, considered as an error since the serverCertificate and the serverSigned1 share the same tag");
        return eFatal;
    }

    //Search the serverCertificate TLV
    //Pointer of serverSignature1 is passed as TLV as serverCertificate contains a repeated TAG
    if ((rc = tlv_data_extractor__tlv_big_size_ref(ASN1_DER_SEQUENCE, initiate_authentication_ok_esipa->server_signature_1, buffer_size - (uint32_t)(initiate_authentication_ok_esipa->server_signature_1 - buffer), NULL, &initiate_authentication_ok_esipa->server_certificate, &initiate_authentication_ok_esipa->server_certificate_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the serverCertificate, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] serverCertificate TLV", initiate_authentication_ok_esipa->server_certificate, (size_t) initiate_authentication_ok_esipa->server_certificate_size);

#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
    //Search the ctxParams1 VALUE
    if ((rc = tlv_data_extractor__tlv_value_medium_size_ref(CONTEXT_CONSTRUCTED_2,  buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &initiate_authentication_ok_esipa->ctx_params_1_value, &initiate_authentication_ok_esipa->ctx_params_1_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the ctxParams1, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] ctxParams1 VALUE", initiate_authentication_ok_esipa->ctx_params_1_value, (size_t) initiate_authentication_ok_esipa->ctx_params_1_value_size);

#else
    //Search the matchingId [OPTIONAL]
    if ((rc = tlv_data_extractor__tlv_value_small_size_ref(ASN1_DER_UTF8_STRING, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, &initiate_authentication_ok_esipa->field_is_present.matching_id, &initiate_authentication_ok_esipa->matching_id, &initiate_authentication_ok_esipa->matching_id_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_ok_esipa] Error extracting the matchingId, rc %d", rc);
        return rc;
    }
    if (initiate_authentication_ok_esipa->field_is_present.matching_id) {
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__initiate_authentication_ok_esipa] matchingId", initiate_authentication_ok_esipa->matching_id, (size_t) initiate_authentication_ok_esipa->matching_id_size);
    } else {
        LOGD("[esipa_tlv_extractor__initiate_authentication_ok_esipa] matchingId is not present");
    }
#endif

    return eOk;
}

static ErrCode esipa_tlv_extractor__initiate_authentication_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_error_esipa_t* error) {
    ErrCode rc;
    uint8_t initiate_authentication_error;

    if ((rc = tlv_data_extractor__result_code(INITIATE_AUTHENTICATION_ERROR_ESIPA, buffer, buffer_size, NULL, &initiate_authentication_error)) != eOk) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_error_esipa] Error extracting the initiateAuthenticationErrorEsipa , rc %d", rc);
        return rc;
    }

    if (initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_DP_ADDRESS && 
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_EUICC_VERSION_NOT_SUPPORTED_BY_DP && 
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED && 
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_ADDRESS_MISMATCH &&
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_OID_MISMATCH &&
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_EIM_TRANSACTION_ID &&
        initiate_authentication_error != INITIATE_AUTHENTICATION_ERROR_ESIPA_UNDEFINED_ERROR) {
        LOGE("[esipa_tlv_extractor__initiate_authentication_error_esipa] initiateAuthenticationErrorEsipa %02X not defined in the InitiateAuthenticationResponseEsipa", initiate_authentication_error);
        return eFatal;
    }

    *error = initiate_authentication_error;
    LOGD("[esipa_tlv_extractor__initiate_authentication_error_esipa] initiateAuthenticationErrorEsipa=%d", *error);

    return eOk;
}

static ErrCode esipa_tlv_extractor__authenticate_client_ok_dp_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_ok_dp_esipa_t* authenticate_client_ok_dp_esipa) {
     ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;

    if (!buffer || buffer_size == 0) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] AuthenticateClientOkDpEsipa is empty/null");
        return eBadArg;
    }

    //Search the AuthenticateClientOkDpEsipa TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, AUTHENTICATE_CLIENT_OK_DP_ESIPA);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] TAG of AuthenticateClientOkDpEsipa (%04X) not found", AUTHENTICATE_CLIENT_OK_DP_ESIPA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] AuthenticateClientOkDpEsipa value", buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset);

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    //Search the transactionId [OPTIONAL]
    if ((rc = tlv_data_extractor__transaction_id(AUTHENTICATE_CLIENT_OK_ESIPA_TRANSACTION_ID,
                                                buffer + tlv_value_offset,
                                                buffer_size - (uint32_t) tlv_value_offset,
                                                &authenticate_client_ok_dp_esipa->field_is_present.transaction_id,
                                                &authenticate_client_ok_dp_esipa->transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the transactionId, rc %d", rc);
        return rc;
    }
#endif

#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
    //Search the profileMetaData TLV
    if ((rc = tlv_data_extractor__tlv_big_size_ref(STORE_METADATA,  buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &authenticate_client_ok_dp_esipa->profile_metadata, &authenticate_client_ok_dp_esipa->profile_metadata_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the profileMetaData, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] profileMetaData TLV", authenticate_client_ok_dp_esipa->profile_metadata, (size_t) authenticate_client_ok_dp_esipa->profile_metadata_size);
#endif

    //Search the smdpSigned2 TLV
    if ((rc = tlv_data_extractor__tlv_big_size_ref(ASN1_DER_SEQUENCE, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &authenticate_client_ok_dp_esipa->smdp_signed_2, &authenticate_client_ok_dp_esipa->smdp_signed_2_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the smdpSigned2, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] smdpSigned2 TLV", authenticate_client_ok_dp_esipa->smdp_signed_2, (size_t) authenticate_client_ok_dp_esipa->smdp_signed_2_size);

    //Search the smdpSignature2 TLV
    if ((rc = tlv_data_extractor__tlv_small_size_ref(SIGNATURE, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &authenticate_client_ok_dp_esipa->smdp_signature_2, &authenticate_client_ok_dp_esipa->smdp_signature_2_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the smdpSignature2, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] smdpSignature2 TLV", authenticate_client_ok_dp_esipa->smdp_signature_2, (size_t) authenticate_client_ok_dp_esipa->smdp_signature_2_size);

    if (authenticate_client_ok_dp_esipa->smdp_signed_2 > authenticate_client_ok_dp_esipa->smdp_signature_2) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] smdpSigned2 found after smdpSignature2, considered as an error since the smdpCertificate and the smdpSigned2 share the same tag");
        return eFatal;
    }

    //Search the smdpCertificate TLV
    //Pointer of smdpSignature2 is passed as TLV as smdpCertificate contains a repeated TAG
    if ((rc = tlv_data_extractor__tlv_big_size_ref(ASN1_DER_SEQUENCE, authenticate_client_ok_dp_esipa->smdp_signature_2, buffer_size - (uint32_t)(authenticate_client_ok_dp_esipa->smdp_signature_2 - buffer), NULL, &authenticate_client_ok_dp_esipa->smdp_certificate, &authenticate_client_ok_dp_esipa->smdp_certificate_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the smdpCertificate, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] smdpCertificate TLV", authenticate_client_ok_dp_esipa->smdp_certificate, (size_t) authenticate_client_ok_dp_esipa->smdp_certificate_size);

    //Search the hashCc TLV
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(HASH_CC, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, &authenticate_client_ok_dp_esipa->field_is_present.hash_cc, authenticate_client_ok_dp_esipa->hash_cc.hash, sizeof(authenticate_client_ok_dp_esipa->hash_cc.hash), NULL)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] Error extracting the hashCc, rc %d", rc);
        return rc;
    }

    if (authenticate_client_ok_dp_esipa->field_is_present.hash_cc) {
        LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] hashCc TLV", authenticate_client_ok_dp_esipa->hash_cc.hash, sizeof(authenticate_client_ok_dp_esipa->hash_cc.hash));
    } else {
        LOGD("[esipa_tlv_extractor__authenticate_client_ok_dp_esipa] hashCc not present");
    }

    return eOk; 
}

static ErrCode esipa_tlv_extractor__authenticate_client_ok_ds_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_ok_ds_esipa_t* authenticate_client_ok_ds_esipa) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    
    if (!buffer || buffer_size == 0) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] AuthenticateClientOkDsEsipa is empty/null");
        return eBadArg;
    }

    //Search the AuthenticateClientOkDsEsipa TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, AUTHENTICATE_CLIENT_OK_DS_ESIPA);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] TAG of AuthenticateClientOkDsEsipa (%04X) not found", AUTHENTICATE_CLIENT_OK_DS_ESIPA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] AuthenticateClientOkDsEsipa value", buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset);

    //Search the transactionId 
    if ((rc = tlv_data_extractor__transaction_id(AUTHENTICATE_CLIENT_OK_ESIPA_TRANSACTION_ID, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &authenticate_client_ok_ds_esipa->transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] Error extracting the transactionId, rc %d", rc);
        return rc;
    }

    // Search the profileDownloadTrigger
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, tlv_value_offset, PROFILE_DOWNLOAD_TRIGGER);
    if (tlv_offset < 0) {
        authenticate_client_ok_ds_esipa->field_is_present.profile_download_trigger = false;
        LOGD("[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] profileDownloadTrigger not present");
    } else {
        if ((rc = esipa_tlv_extractor__profile_download_trigger_request(buffer + tlv_offset, buffer_size - (uint32_t) tlv_offset, &authenticate_client_ok_ds_esipa->profile_download_trigger)) != eOk) {
            LOGE("[esipa_tlv_extractor__authenticate_client_ok_ds_esipa] Error extracting the profileDownloadTrigger, rc %d", rc);
            return rc;
        }
        authenticate_client_ok_ds_esipa->field_is_present.profile_download_trigger = true;
    }

    return eOk;
}

static ErrCode esipa_tlv_extractor__authenticate_client_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_error_esipa_t* error) {
    ErrCode rc;
    uint8_t authenticate_client_error;

    if ((rc = tlv_data_extractor__result_code(AUTHENTICATE_CLIENT_ERROR_ESIPA, buffer, buffer_size, NULL, &authenticate_client_error)) != eOk) {
        LOGE("[esipa_tlv_extractor__authenticate_client_error_esipa] Error extracting the authenticateClientErrorEsipa , rc %d", rc);
        return rc;
    }

    if (authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_INVALID && 
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_EXPIRED && 
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_INVALID && 
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_EXPIRED &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_SIGNATURE_INVALID &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_MATCHING_ID_REFUSED &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EID_MISMATCH &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_NO_ELIGIBLE_PROFILE &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_CI_PK_UNKNOWN &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_INVALID_TRANSACTION_ID &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_INSUFFICIENT_MEMORY &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_PPR_NOT_ALLOWED &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_EVENT_ID_UNKNOWN &&
        authenticate_client_error != AUTHENTICATE_CLIENT_ERROR_ESIPA_UNDEFINED_ERROR) {
        LOGE("[esipa_tlv_extractor__authenticate_client_error_esipa] authenticateClientErrorEsipa %02X not defined in the AuthenticateClientResponseEsipa", authenticate_client_error);
        return eFatal;
    }

    *error = authenticate_client_error;
    LOGD("[esipa_tlv_extractor__authenticate_client_error_esipa] authenticateClientErrorEsipa=%d", *error);

    return eOk;
}

static ErrCode esipa_tlv_extractor__get_bound_profile_package_ok_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_ok_esipa_t* get_bound_profile_package_ok_esipa) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;

    if (!buffer || buffer_size == 0) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] getBoundProfilePackageOkEsipa is empty/null");
        return eBadArg;
    }

    //Search the getBoundProfilePackageOkEsipa TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, GET_BOUND_PROFILE_PACKAGE_OK_ESIPA);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] TAG of getBoundProfilePackageOkEsipa (%04X) not found", GET_BOUND_PROFILE_PACKAGE_OK_ESIPA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] getBoundProfilePackageOkEsipa value", buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset);

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    //Search the transactionId 
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_0, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &get_bound_profile_package_ok_esipa->transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] Error extracting the transactionId, rc %d", rc);
        return rc;
    }
#endif

    //Search the BoundProfilePackage TLV
    if ((rc = tlv_data_extractor__tlv_big_size_ref(BOUND_PROFILE_PKG, buffer + tlv_value_offset, buffer_size - (uint32_t) tlv_value_offset, NULL, &get_bound_profile_package_ok_esipa->bound_profile_package, &get_bound_profile_package_ok_esipa->bound_profile_package_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] Error extracting the BoundProfilePackage, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__get_bound_profile_package_ok_esipa] BoundProfilePackage TLV", get_bound_profile_package_ok_esipa->bound_profile_package, get_bound_profile_package_ok_esipa->bound_profile_package_size);

    return eOk;
}

static ErrCode esipa_tlv_extractor__get_bound_profile_package_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_error_esipa_t* error) {
    ErrCode rc;
    uint8_t get_bound_profile_package_error;

    if ((rc = tlv_data_extractor__result_code(GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA, buffer, buffer_size, NULL, &get_bound_profile_package_error)) != eOk) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_error_esipa] Error extracting the getBoundProfilePackageErrorEsipa , rc %d", rc);
        return rc;
    }

    if (get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_EUICC_SIGNATURE_INVALID && 
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_MISSING && 
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_REFUSED && 
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_RETRIES_EXCEEDED &&
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_BPP_REBINDING_REFUSED &&
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_DOWNLOAD_ORDER_EXPIRED &&
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_METADATA_MISMATCH &&
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_INVALID_TRANSACTION_ID &&
        get_bound_profile_package_error != GET_BPP_ERROR_ESIPA_UNDEFINED_ERROR) {
        LOGE("[esipa_tlv_extractor__get_bound_profile_package_error_esipa] getBoundProfilePackageErrorEsipa %02X not defined in the GetBoundProfilePackageResponseEsipa", get_bound_profile_package_error);
        return eFatal;
    }

    *error = get_bound_profile_package_error;
    LOGD("[esipa_tlv_extractor__get_bound_profile_package_error_esipa] getBoundProfilePackageErrorEsipa=%d", *error);

    return eOk;
}

static ErrCode esipa_tlv_extractor__cancel_session_error_esipa(const uint8_t* buffer, const uint32_t buffer_size, cancel_session_error_esipa_t* error) {
    ErrCode rc;
    uint8_t cancel_session_error;

    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_1, buffer, buffer_size, NULL, &cancel_session_error)) != eOk) {
        LOGE("[esipa_tlv_extractor__cancel_session_error_esipa] Error extracting the cancelSessionError, rc %d", rc);
        return rc;
    }

    if (cancel_session_error != CANCEL_SESSION_ERROR_ESIPA_INVALID_TRANSACTION_ID && 
        cancel_session_error != CANCEL_SESSION_ERROR_ESIPA_EUICC_SIGNATURE_INVALID && 
        cancel_session_error != CANCEL_SESSION_ERROR_ESIPA_UNDEFINED_ERROR) {
        LOGE("[esipa_tlv_extractor__cancel_session_error_esipa] cancelSessionError %02X not defined in the CancelSessionResponseEsipa", cancel_session_error);
        return eFatal;
    }

    *error = cancel_session_error;
    LOGD("[esipa_tlv_extractor__cancel_session_error_esipa] authenticateClientErrorEsipa=%d", *error);

    return eOk;
}
#endif

static ErrCode esipa_tlv_extractor__euicc_package_signed(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_signed_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] EuiccPackageSigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageSigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(ASN1_DER_SEQUENCE, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error extracting the EuiccPackageSigned TLV value");
        return rc;
    }

    // Parse eimId
    if ((rc = tlv_data_extractor__tlv_value_small_size_ref(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, &obj->eim_id, &obj->eim_id_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error extracting the eimId, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_signed] eimId", obj->eim_id, obj->eim_id_size);

    // Parse eidValue
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(EID, tlv_value, tlv_value_size, NULL, obj->eid.eid, sizeof(obj->eid.eid), NULL)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error extracting the eidValue, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_signed] eidValue", obj->eid.eid, sizeof(obj->eid.eid));

    // Parse counterValue
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_1, tlv_value, tlv_value_size, NULL, &obj->counter_value)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error parsing the counterValue, rc %d", rc);
        return rc;
    }
    LOGD("[esipa_tlv_extractor__euicc_package_signed] counterValue %u", obj->counter_value);

    // Parse eimTransactionId
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, &obj->field_is_present.eim_transaction_id, &obj->eim_transaction_id)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error extracting the eimTransactionId, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_transaction_id) {
        LOG_DATA(eLogDebug, "[esipa_tlv_extractor__euicc_package_signed] eimTransactionId", obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size);
    } else {
        LOGD("[esipa_tlv_extractor__euicc_package_signed] The eimTransactionId is not present");
    }

    // Parse euiccPackage
    if ((rc = esipa_tlv_extractor__euicc_package(tlv_value, tlv_value_size, &obj->euicc_package)) != eOk) {
        LOGE("[esipa_tlv_extractor__euicc_package_signed] Error parsing the euiccPackage, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_tlv_extractor__euicc_package(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_t* obj) {
    int offset;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__euicc_package] EuiccPackage object is null");
        return eBadArg;
    }

    // Parse EuiccPackage. Not in a switch because the choice does not have his own tag
    if ((offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, CONTEXT_CONSTRUCTED_0)) >= 0) {
        // psmoList
        obj->choice = EUICC_PACKAGE_CHOICE_PSMO_LIST;
        return tlv_data_extractor__asn1_list_init(&obj->value.psmo_list, CONTEXT_CONSTRUCTED_0, 0, buffer + offset, buffer_size - (uint32_t) offset);
    } else if ((offset = ber_tlv_parser__find_tlv_by_tag_2(buffer, buffer_size, 0, CONTEXT_CONSTRUCTED_1)) >= 0) {
        // ecoList
        obj->choice = EUICC_PACKAGE_CHOICE_ECO_LIST;
        return tlv_data_extractor__asn1_list_init(&obj->value.eco_list, CONTEXT_CONSTRUCTED_1, 0, buffer + offset, buffer_size - (uint32_t) offset);
    } else {
        LOGE("[esipa_tlv_extractor__euicc_package] EuiccPackage CHOICE not found");
        return eFatal;
    }
}

static ErrCode esipa_tlv_extractor__eim_package_error(const uint8_t* buffer, const uint32_t buffer_size, eim_package_error_from_eim_to_ipa_t* error) {
    ErrCode rc;
    uint8_t eim_package_error;

    if ((rc = tlv_data_extractor__result_code(ASN1_DER_INTEGER, buffer, buffer_size, NULL, &eim_package_error)) != eOk) {
        LOGE("[esipa_tlv_extractor__eim_package_error] Error extracting the eimPackageError, rc %d", rc);
        return rc;
    }

    switch (eim_package_error)
    {
    case EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE:
    case EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_EID_NOT_FOUND:
    case EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_INVALID_EID:
    case EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_MISSING_EID:
    case EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_UNDEFINED_ERROR:
        *error = eim_package_error;
        LOGD("[esipa_tlv_extractor__eim_package_error] eimPackageError=%d", *error);
        return eOk;
    default:
        LOGE("[esipa_tlv_extractor__eim_package_error] eimPackageError %02X not defined in the GetEimPackageResponse", eim_package_error);
        return eFatal;
    }
}

static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_tag_list(const uint8_t* buffer, const uint32_t buffer_size, ipa_euicc_data_request_tag_list_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    uint32_t offset = 0;
    unsigned short tag;
    uint8_t tag_size;

    if (!obj) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] tagList object is null");
        return eBadArg;
    }
    memset(obj, 0, sizeof(ipa_euicc_data_request_tag_list_t)); // To set all the tags to not found

    // Get the tagList VALUE
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(TAG_LIST, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request] Error on extract the value of the tagList TLV, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__ipa_euicc_data_request] tagList value", tlv_value, tlv_value_size);

    //Fill the tagList object with the tags that are present in the tagList TLV
    while (offset < tlv_value_size) {
        if ((rc = ber_tlv_parser__get_tag_data(tlv_value, tlv_value_size, offset, &tag, &tag_size)) != eOk) {
            LOGW("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] Error getting the next tag of the list at offset %u, rc %d", offset, rc);
            return eOk;
        }
        switch (tag)
        {
        case IPA_EUICC_DATA_LIST_OF_NOTIF:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of List of Notifications is present");
            obj->notifications_list = true;
            break;
        case IPA_EUICC_DATA_DEFAULT_SMDP:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of Default SM-DP+ address is present");
            obj->default_smdp = true;
            break;
        case IPA_EUICC_DATA_EUICC_PKG_RESULTS:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of eUICC Package Results is present");
            obj->euicc_package_results = true;
            break;
        case EUICC_INFO_1:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of eUICCInfo1 is present");
            obj->euicc_info_1 = true;
            break;
        case EUICC_INFO_2:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of eUICCInfo2 is present");
            obj->euicc_info_2 = true;
            break;
        case IPA_EUICC_DATA_ROOT_SMDS:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of Root SM-DS address is present");
            obj->root_smds = true;
            break;
        case IPA_EUICC_DATA_ASSOCIATION_TOKEN:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of Association token is present");
            obj->association_token = true;
            break;
        case IPA_EUICC_DATA_EUM_CERT:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of EUM certificate is present");
            obj->eum_cert = true;
            break;
        case IPA_EUICC_DATA_EUICC_CERT:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of eUICC certificate is present");
            obj->euicc_cert = true;
            break;
        case IPA_EUICC_DATA_IPA_CAPABILITES:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of IPA Capabilities is present");
            obj->ipa_capabilities = true;
            break;
        case IPA_EUICC_DATA_DEVICE_INFO:
            LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] TAG of Device Information is present");
            obj->device_information = true;
            break;
        default:
            // Any tag that is present in the tagList of IpaEuiccDataRequest, but is not in the list of tags above, is ignored without error.
            LOGW("[esipa_tlv_extractor__ipa_euicc_data_request_tag_list] Unknown TAG (%04X) inside the tagList TLV", tag);
            break;
        }
        offset += (uint32_t) tag_size;
    }

    return eOk;
}

static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, search_criteria_notification_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification] searchCriteriaNotification object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(tag, buffer, buffer_size, tlv_is_present, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification] Error extracting the searchCriteriaNotification child TLV, rc %d", rc);
        return rc;
    }

    if (tlv_is_present && !(*tlv_is_present)) {
        LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification] The searchCriteriaNotification is not present");
        return eOk; // If the TLV is not present we don't need to do anything else
    }

    switch (child_tag)
    {
    case CONTEXT_PRIMITIVE_0:
        obj->choice = ESIPA_NOTIFICATION_SEQ_NUMBER_CHOICE;
        return tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_0, child_tlv, child_tlv_size, NULL, &obj->value.seq_number);
    case CONTEXT_PRIMITIVE_1:
        obj->choice = ESIPA_NOTIFICATION_PROFILE_MANAGEMENT_OPERATION_CHOICE;
        return es10_tlv_extractor__notification_event(CONTEXT_PRIMITIVE_1, child_tlv, child_tlv_size, &obj->value.profile_management_operation);
    default:
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_notification] Unknown searchCriteriaNotification CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

static ErrCode esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, search_criteria_euicc_package_result_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;
    
    if (!obj) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result] searchCriteriaEuiccPackageResult object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(tag, buffer, buffer_size, tlv_is_present, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result] Error extracting the searchCriteriaEuiccPackageResult child TLV, rc %d", rc);
        return rc;
    }

    if (tlv_is_present && !(*tlv_is_present)) {
        LOGD("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result] The searchCriteriaEuiccPackageResult is not present");
        return eOk; // If the TLV is not present we don't need to do anything else
    }

    switch (child_tag)
    {
    case CONTEXT_PRIMITIVE_0:
        obj->choice = ESIPA_EUICC_PACKAGE_RESULT_SEQ_NUMBER_CHOICE;
        return tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_0, child_tlv, child_tlv_size, NULL, &obj->value.seq_number);
    default:
        LOGE("[esipa_tlv_extractor__ipa_euicc_data_request_search_criteria_euicc_package_result] Unknown searchCriteriaEuiccPackageResult CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
/** This function extracts data from a ProfileDownloadData TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the ProfileDownloadData TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[in]  tag TAG of the ProfileDownloadData TLV
 * @param[out] profile_download_data A pointer to a profile_download_data_t structure initialized with PROFILE_DOWNLOAD_DATA_INITIALIZER. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
static ErrCode esipa_tlv_extractor__profile_download_data(const uint8_t* buffer, const uint32_t buffer_size, const unsigned short tag, profile_download_data_t* profile_download_data) {
    ErrCode rc;
    int tlv_offset = 0;
    size_t tlv_value_offset = 0;
    _BerTlv tlv_child_obj;

    if (!buffer || buffer_size == 0) {
        LOGE("[esipa_tlv_extractor__profile_download_data] profileDownloadData is empty/null");
        return eBadArg;
    }

    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2((uint8_t*) buffer, buffer_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[esipa_tlv_extractor__profile_download_data] TAG of profileDownloadData (%02X) not found", tag);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(buffer, (size_t) tlv_offset);
    LOGD("[esipa_tlv_extractor__profile_download_data] profileDownloadData value at offset %u", tlv_value_offset);

    if ((rc = ber_tlv_parser__ber_tlv_2(buffer, buffer_size, tlv_value_offset, &tlv_child_obj)) != eOk) {
        LOGE("[esipa_tlv_extractor__profile_download_data] Error parsing the profileDownloadData value to TLV from the profileDownloadTriggerRequest TLV on offset %u, rc %d", (unsigned int) tlv_value_offset, rc);
        return eFatal;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_extractor__profile_download_data] profileDownloadData Value", buffer + tlv_value_offset, tlv_child_obj.nTag + tlv_child_obj.nLength + tlv_child_obj.length);

    switch (tlv_child_obj.tag)
    {
    case PROFILE_DOWNLOAD_DATA_ACTIVATION_CODE:
        LOGD("[esipa_tlv_extractor__profile_download_data] profileDownloadData CHOICE activationCode");
        profile_download_data->choice = ACTIVATION_CODE_CHOICE;
        profile_download_data->data = buffer + tlv_value_offset + tlv_child_obj.nTag + tlv_child_obj.nLength;
        profile_download_data->data_len = (uint32_t) tlv_child_obj.length;
        LOG_UTF8_DATA(eLogDebug, "[esipa_tlv_extractor__profile_download_data] activationCode: ", profile_download_data->data, profile_download_data->data_len);
        return eOk;

    case PROFILE_DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP:
        LOGD("[esipa_tlv_extractor__profile_download_data] profileDownloadData CHOICE contactDefaultSmdp");
        profile_download_data->choice = CONTACT_DEFAULT_SMDP_CHOICE;
        return eOk;

    case PROFILE_DOWNLOAD_DATA_CONTACT_SMDS:
        LOGD("[esipa_tlv_extractor__profile_download_data] profileDownloadData CHOICE contactSmds"); 
        profile_download_data->choice = CONTACT_SMDS_CHOICE;
        if (tlv_child_obj.length == 0) {
            LOGD("[esipa_tlv_extractor__profile_download_data] smdsAddress is not present"); 
            profile_download_data->data = NULL;
            profile_download_data->data_len = 0;
        } else {
            //Search smdsAddress
            tlv_value_offset += (size_t) tlv_child_obj.nTag + (size_t) tlv_child_obj.nLength;
            if ((rc = ber_tlv_parser__ber_tlv_2(buffer, buffer_size, tlv_value_offset, &tlv_child_obj)) != eOk) {
                LOGE("[esipa_tlv_extractor__profile_download_data] Error parsing the smdsAddress value to TLV from the profileDownloadTriggerRequest TLV on offset %u, rc %d", (unsigned int) tlv_value_offset, rc);
                return rc;
            }
            profile_download_data->data = buffer + (uint32_t) tlv_value_offset + (uint32_t) tlv_child_obj.nTag + (uint32_t) tlv_child_obj.nLength;
            profile_download_data->data_len = (uint32_t) tlv_child_obj.length;
            LOG_UTF8_DATA(eLogDebug, "[esipa_tlv_extractor__profile_download_data] smdsAddress", profile_download_data->data, profile_download_data->data_len);
        }
        return eOk;
    
    default:
        LOGE("[esipa_tlv_extractor__profile_download_trigger_request] TAG of profileDownloadData value (%02X) is invalid", tlv_child_obj.tag);
        return eFatal;
    }
}
#endif 

static ErrCode esipa_tlv_extractor__empty_response(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size) {
    ErrCode rc;
    bool value_is_empty;

    if ((rc = tlv_data_extractor__tlv_value_is_empty(tag, buffer, buffer_size, &value_is_empty)) != eOk) {
        LOGE("[esipa_tlv_extractor__empty_response] Error on check if the value is empty or not for the emptyResponse TLV, rc %d", rc);
        return rc;
    }

    if (value_is_empty) {
        return eOk;
    } else {
        LOGE("[esipa_tlv_extractor__empty_response] The emptyResponse TLV is not an empty TLV");
        return eFatal;
    }
}

static ErrCode esipa_tlv_extractor__provide_eim_package_result_error(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, provide_eim_package_result_error_t* error) {
    ErrCode rc;
    uint8_t tlv_error_value;

    if (!error) {
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_error] provideEimPackageResultError enum is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__result_code(tag, buffer, buffer_size, NULL, &tlv_error_value)) != eOk) {
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_error] Error extracting the provideEimPackageResultError, rc %d", rc);
        return rc;
    }

    switch (tlv_error_value)
    {
    case PROVIDE_EIM_PKG_RESULT_ERROR_EID_NOT_FOUND:
    case PROVIDE_EIM_PKG_RESULT_ERROR_INVALID_EID:
    case PROVIDE_EIM_PKG_RESULT_ERROR_MISSING_EID:
    case PROVIDE_EIM_PKG_RESULT_ERROR_UNDEFINED_ERROR:
        *error = tlv_error_value;
        LOGD("[esipa_tlv_extractor__provide_eim_package_result_error] provideEimPackageResultError=%d", *error);
        return eOk;
    default:
        LOGE("[esipa_tlv_extractor__provide_eim_package_result_error] provideEimPackageResultError %02X not defined", tlv_error_value);
        return eFatal;
    }
}

static inline ErrCode esipa_tlv_extractor__subject_key_identifier_possibly_truncated(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, bool* tlv_is_present, subject_key_identifier_possibly_truncated_t* obj) {
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    return tlv_data_extractor__tlv_value_small_size_copy(tag, buffer, buffer_size, tlv_is_present, obj->subject_key_identifier.value, sizeof(obj->subject_key_identifier.value), &obj->subject_key_identifier.size);
#else
    return tlv_data_extractor__subject_key_identifier(tag, buffer, buffer_size, tlv_is_present, &obj->subject_key_identifier);
#endif
}
