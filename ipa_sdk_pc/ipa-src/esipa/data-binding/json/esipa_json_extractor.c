/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef ENABLE_ESIPA_JSON
#include "esipa_json_extractor.h"
#include "json_data_extractor.h"
#include "gsma_json_extractor.h"
#include "base64.h"
#include "esipa_tlv_extractor.h"
#include "tlv_data_extractor.h"
#include "tlv_tags.h"
#include "log.h"

#define EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY "euiccPackageRequest"
#define IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY "ipaEuiccDataRequest"
#define EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY "eimAcknowledgements"
#define PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY "profileDownloadTriggerRequest"
#define EIM_PACKAGE_ERROR_ESIPA_JSON_KEY "eimPackageError"
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
#define TRANSACION_ID_ESIPA_JSON_KEY "transactionId"
#endif
#define SERVER_SIGNED_1_ESIPA_JSON_KEY "serverSigned1"
#define SERVER_SIGNATURE_1_ESIPA_JSON_KEY "serverSignature1"
#define EUICC_CI_PK_IDENTIFIER_ESIPA_JSON_KEY "euiccCiPKIdentifierToBeUsed"
#define SERVER_CERTIFICATE_ESIPA_JSON_KEY "serverCertificate"
#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
#define CTX_PARAMS_1_ESIPA_JSON_KEY "ctxParams1"
#else
#define MATCHING_ID_ESIPA_JSON_KEY "matchingId"
#endif
#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
#define PROFILE_METADATA_ESIPA_JSON_KEY "profileMetadata"
#endif
#define SMDP_SIGNED_2_ESIPA_JSON_KEY "smdpSigned2"
#define SMDP_SIGNATURE_2_ESIPA_JSON_KEY "smdpSignature2"
#define SMDP_CERTIFICATE_ESIPA_JSON_KEY "smdpCertificate"
#define HASH_CC_ESIPA_JSON_KEY "hashCc"
#define PROFILE_DOWNLOAD_TRIGGER_ESIPA_JSON_KEY "profileDownloadTrigger"
#define BOUND_PROFILE_PACKAGE_ESIPA_JSON_KEY "boundProfilePackage"
#endif

static ErrCode esipa_json_extractor__expected_response(esipa_message_from_ipa_to_eim_choice_t in, esipa_message_from_eim_to_ipa_choice_t* out);
static ErrCode esipa_json_extractor__get_eim_package_response_body(unsigned char* json, uint32_t json_len, get_eim_package_response_t* obj);
static ErrCode esipa_json_extractor__get_eim_package_response_error(gsma_json_response_header_t* header, enum eim_package_error_from_eim_to_ipa_e* obj);
static ErrCode esipa_json_extractor__provide_eim_package_result_response_body(unsigned char* json, uint32_t json_len, provide_eim_package_result_response_t* obj);
static ErrCode esipa_json_extractor__provide_eim_package_result_response_error(gsma_json_response_header_t* header, enum provide_eim_package_result_error_e* obj);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_json_extractor__initiate_authentication_response_esipa_ok_body(unsigned char* json, uint32_t json_len, initiate_authentication_ok_esipa_t* obj);
static ErrCode esipa_json_extractor__initiate_authentication_response_esipa_error(gsma_json_response_header_t* header, enum initiate_authentication_error_esipa_e* obj);
static ErrCode esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body(unsigned char* json, uint32_t json_len, authenticate_client_ok_dp_esipa_t* obj);
static ErrCode esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body(unsigned char* json, uint32_t json_len, authenticate_client_ok_ds_esipa_t* obj);
static ErrCode esipa_json_extractor__authenticate_client_response_esipa_error(gsma_json_response_header_t* header, enum authenticate_client_error_esipa_e* obj);
static ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa_ok_body(unsigned char* json, uint32_t json_len, get_bound_profile_package_ok_esipa_t* obj);
static ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa_error(gsma_json_response_header_t* header, enum get_bound_profile_package_error_esipa_e* obj);
static ErrCode esipa_json_extractor__cancel_session_response_esipa_error(gsma_json_response_header_t* header, enum cancel_session_error_esipa_e* obj);
#endif

ErrCode esipa_json_extractor__esipa_message_from_eim_to_ipa_choice(unsigned char* json, uint32_t json_len, esipa_message_from_ipa_to_eim_choice_t last_message_sent, esipa_message_from_eim_to_ipa_choice_t* result) {
    ErrCode rc = eFatal;
    unsigned char* json_value = NULL;
    uint32_t json_value_len = 0;
    int num_value = 0;
    
    if (eOk != (rc = json_data_extractor__get_string_value(json, json_len, "header", &json_value, &json_value_len))) { // Is the only Esipa message that can not contain the header
        *result = TRANSFER_EIM_PACKAGE_REQUEST_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = GET_EIM_PACKAGE_RESPONSE_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = GET_EIM_PACKAGE_RESPONSE_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = GET_EIM_PACKAGE_RESPONSE_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_int_value(json, json_len, EIM_PACKAGE_ERROR_ESIPA_JSON_KEY, &num_value))) {
        *result = GET_EIM_PACKAGE_RESPONSE_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE;
    }
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, SERVER_SIGNED_1_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = INITIATE_AUTHENTICATION_RESPONSE_ESIPA_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNED_2_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = AUTHENTICATE_CLIENT_RESPONSE_ESIPA_CHOICE;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, BOUND_PROFILE_PACKAGE_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        *result = GET_BOUND_PROFILE_PACKAGE_RESPONSE_ESIPA_CHOICE;
    }
#endif
    else { // No JSON key available to recognize the message
        return esipa_json_extractor__expected_response(last_message_sent, result);
    }

    return eOk;
}

ErrCode esipa_json_extractor__transfer_eim_package_request(unsigned char* json, uint32_t json_len, transfer_eim_package_request_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* base64 = NULL;
    uint32_t base64_len = 0;
    int32_t tlv_size = 0;

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__transfer_eim_package_request] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__transfer_eim_package_request] ", json, json_len);

    /* Extract the JSON requestBody CHOICE */
    if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__transfer_eim_package_request] %s found", EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY);
        obj->choice = EUICC_PACKAGE_REQUEST_CHOICE_TEPR;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__transfer_eim_package_request] %s found", IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY);
        obj->choice = IPA_EUICC_DATA_REQUEST_CHOICE_TEPR;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__transfer_eim_package_request] %s found", EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY);
        obj->choice = EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__transfer_eim_package_request] %s found", PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY);
        obj->choice = PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR;
    } else {
        LOG_UTF8_DATA(eLogErr, "[esipa_json_extractor__transfer_eim_package_request] TransferEimPackage JSON requestBody not supported: ", json, json_len);
        return eNotSupported;
    }

    /* Parse the base64 in place, overwriting the json string buffer */
    if ((tlv_size = base64__decode(base64, base64_len, base64, base64_len)) < 0) {
        LOGE("[esipa_json_extractor__transfer_eim_package_request] Error parsing the base64 string, err %d", tlv_size);
        return eFatal;
    }
 
    /* Extract the TLV data */
    switch (obj->choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_TEPR:
        obj->value.euicc_package_request.euicc_package_request = (uint8_t*) base64;
        obj->value.euicc_package_request.euicc_package_request_size = (uint32_t) tlv_size;
        break;
    case IPA_EUICC_DATA_REQUEST_CHOICE_TEPR:
        rc = esipa_tlv_extractor__ipa_euicc_data_request((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.ipa_euicc_data_request);
        break;
    case EIM_ACKNOWLEDGEMENTS_CHOICE_TEPR:
        rc = esipa_tlv_extractor__eim_acknowledgements((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.eim_acknowledgements);
        break;
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_TEPR:
        rc = esipa_tlv_extractor__profile_download_trigger_request((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.profile_download_trigger_request);
        break;
    default:
        LOGE("[esipa_json_extractor__transfer_eim_package_request] Unknown TransferEimPackage JSON requestBody CHOICE: %d", obj->choice);
        return eNotSupported;
    }

    if (rc != eOk) {
        LOGE("[esipa_json_extractor__transfer_eim_package_request] Error on parse the JSON requestBody TLV for the %d choice, err %d", obj->choice, rc);
        return eInvalidFormat;
    }

    return eOk;
}

ErrCode esipa_json_extractor__get_eim_package_response(unsigned char* json, uint32_t json_len, get_eim_package_response_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__get_eim_package_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_eim_package_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__get_eim_package_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        return esipa_json_extractor__get_eim_package_response_body(json, json_len, obj);
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = EIM_PACKAGE_ERROR_CHOICE_GEPR;
        return esipa_json_extractor__get_eim_package_response_error(&header, &obj->value.eim_package_error);
    } else {
        LOGE("[esipa_json_extractor__get_eim_package_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode esipa_json_extractor__provide_eim_package_result_response(unsigned char* json, uint32_t json_len, provide_eim_package_result_response_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__provide_eim_package_result_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__provide_eim_package_result_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__provide_eim_package_result_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        return esipa_json_extractor__provide_eim_package_result_response_body(json, json_len, obj);
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = PROVIDE_EIM_PACKAGE_RESULT_ERROR_CHOICE_PEPRR;
        return esipa_json_extractor__provide_eim_package_result_response_error(&header, &obj->value.provide_eim_package_result_error);
    } else {
        LOGE("[esipa_json_extractor__provide_eim_package_result_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
ErrCode esipa_json_extractor__initiate_authentication_response_esipa(unsigned char* json, uint32_t json_len, initiate_authentication_response_esipa_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = INITIATE_AUTHENTICATION_OK_ESIPA_CHOICE;
        return esipa_json_extractor__initiate_authentication_response_esipa_ok_body(json, json_len, &obj->value.initiate_authentication_ok_esipa);
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = INITIATE_AUTHENTICATION_ERROR_ESIPA_CHOICE;
        return esipa_json_extractor__initiate_authentication_response_esipa_error(&header, &obj->value.initiate_authentication_error_esipa);
    } else {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode esipa_json_extractor__authenticate_client_response_esipa(unsigned char* json, uint32_t json_len, authenticate_client_response_esipa_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        unsigned char* json_value = NULL;
        uint32_t json_value_len = 0;
        if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNED_2_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
            obj->choice = AUTHENTICATE_CLIENT_OK_DP_ESIPA_CHOICE;
            return esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body(json, json_len, &obj->value.authenticate_client_ok_dp_esipa);
        } else {
            obj->choice = AUTHENTICATE_CLIENT_OK_DS_ESIPA_CHOICE;
            return esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body(json, json_len, &obj->value.authenticate_client_ok_ds_esipa);
        }
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = AUTHENTICATE_CLIENT_ERROR_ESIPA_CHOICE;
        return esipa_json_extractor__authenticate_client_response_esipa_error(&header, &obj->value.authenticate_client_error_esipa);
    } else {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa(unsigned char* json, uint32_t json_len, get_bound_profile_package_response_esipa_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__get_bound_profile_package_response_esipa] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_bound_profile_package_response_esipa] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__get_bound_profile_package_response_esipa] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = GET_BOUND_PROFILE_PACKAGE_OK_ESIPA_CHOICE;
        return esipa_json_extractor__get_bound_profile_package_response_esipa_ok_body(json, json_len, &obj->value.get_bound_profile_package_ok_esipa);
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA_CHOICE;
        return esipa_json_extractor__get_bound_profile_package_response_esipa_error(&header, &obj->value.get_bound_profile_package_error_esipa);
    } else {
        LOGE("[esipa_json_extractor__get_bound_profile_package_response_esipa] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode esipa_json_extractor__cancel_session_response_esipa(unsigned char* json, uint32_t json_len, cancel_session_response_esipa_t* obj) {
    ErrCode rc = eFatal;
    gsma_json_response_header_t header = { 0 };

    /* Check input parameters */
    if (!json) {
        LOGE("[esipa_json_extractor__cancel_session_response_esipa] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__cancel_session_response_esipa] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[esipa_json_extractor__cancel_session_response_esipa] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = CANCEL_SESSION_OK_ESIPA;
        return eOk;
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = CANCEL_SESSION_ERROR_ESIPA;
        return esipa_json_extractor__cancel_session_response_esipa_error(&header, &obj->cancel_session_error);
    } else {
        LOGE("[esipa_json_extractor__cancel_session_response_esipa] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}
#endif

static ErrCode esipa_json_extractor__expected_response(esipa_message_from_ipa_to_eim_choice_t in, esipa_message_from_eim_to_ipa_choice_t* out) {
    switch (in)
    {
    case GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI:
        *out = GET_EIM_PACKAGE_RESPONSE_CHOICE;
        break;
    case PROVIDE_EIM_PACKAGE_RESULT_CHOICE_EMFI:
        *out = PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE;
        break;
    case TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE_EMFI:
        *out = TRANSFER_EIM_PACKAGE_REQUEST_CHOICE;
        break;
    case HANDLE_NOTIFICATION_ESIPA_CHOICE_EMFI:
        *out = PROVIDE_EIM_PACKAGE_RESULT_RESPONSE_CHOICE; // In case of async protocols like MQTT is the way to send the ACK
        break;
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
    case INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE_EMFI:
        *out = INITIATE_AUTHENTICATION_RESPONSE_ESIPA_CHOICE;
        break;
    case AUTHENTICATE_CLIENT_REQUEST_ESIPA_CHOICE_EMFI:
        *out = AUTHENTICATE_CLIENT_RESPONSE_ESIPA_CHOICE;
        break;
    case GET_BOUND_PROFILE_PACKAGE_REQUEST_ESIPA_CHOICE_EMFI:
        *out = GET_BOUND_PROFILE_PACKAGE_RESPONSE_ESIPA_CHOICE;
        break;
    case CANCEL_SESSION_REQUEST_ESIPA_CHOICE_EMFI:
        *out = CANCEL_SESSION_RESPONSE_ESIPA_CHOICE;
        break;
#endif
    default:
        return eBadArg;
    }
    LOGT("[esipa_json_extractor__expected_response] in: %d, out: %d", in, *out);

    return eOk;
}

static ErrCode esipa_json_extractor__get_eim_package_response_body(unsigned char* json, uint32_t json_len, get_eim_package_response_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* base64 = NULL;
    uint32_t base64_len = 0;
    int32_t tlv_size = 0;
    int num_value = 0;

    /* Extract the JSON requestBody CHOICE */
    if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__get_eim_package_response_body] %s found", EUICC_PACKAGE_REQUEST_ESIPA_JSON_KEY);
        obj->choice = EUICC_PACKAGE_REQUEST_CHOICE_GEPR;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__get_eim_package_response_body] %s found", IPA_EUICC_DATA_REQUEST_ESIPA_JSON_KEY);
        obj->choice = IPA_EUICC_DATA_REQUEST_CHOICE_GEPR;
    } else if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__get_eim_package_response_body] %s found", PROFILE_DOWNLOAD_TRIGGER_REQUEST_ESIPA_JSON_KEY);
        obj->choice = PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR;
    } else if (eOk == (rc = json_data_extractor__get_int_value(json, json_len, EIM_PACKAGE_ERROR_ESIPA_JSON_KEY, &num_value))) {
        LOGD("[esipa_json_extractor__get_eim_package_response_body] %s found, eimPackageError: %d", EIM_PACKAGE_ERROR_ESIPA_JSON_KEY, num_value);
        obj->choice = EIM_PACKAGE_ERROR_CHOICE_GEPR;
    } else {
        LOG_UTF8_DATA(eLogErr, "[esipa_json_extractor__get_eim_package_response_body] GetEimPackage JSON response not supported: ", json, json_len);
        return eNotSupported;
    }

    /* Parse the base64 in place, overwriting the json string buffer */
    if (base64) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_eim_package_response_body] base64: ", base64, base64_len);
        if ((tlv_size = base64__decode(base64, base64_len, base64, base64_len)) < 0) {
            LOGE("[esipa_json_extractor__transfer_eim_package_request] Error parsing the base64 string, err %d", tlv_size);
            return eFatal;
        }
        LOG_DATA(eLogTrace, "[esipa_json_extractor__get_eim_package_response_body] ASN1: ", base64, tlv_size);
    }
 
    /* Extract the TLV data */
    switch (obj->choice)
    {
    case EUICC_PACKAGE_REQUEST_CHOICE_GEPR:
        obj->value.euicc_package_request.euicc_package_request = (uint8_t*) base64;
        obj->value.euicc_package_request.euicc_package_request_size = (uint32_t) tlv_size;
        break;
    case IPA_EUICC_DATA_REQUEST_CHOICE_GEPR:
        rc = esipa_tlv_extractor__ipa_euicc_data_request((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.ipa_euicc_data_request);
        break;
    case PROFILE_DOWNLOAD_TRIGGER_REQUEST_CHOICE_GEPR:
        rc = esipa_tlv_extractor__profile_download_trigger_request((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.profile_download_trigger_request);
        break;
    case EIM_PACKAGE_ERROR_CHOICE_GEPR:
        if (EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE == num_value ||
            EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_EID_NOT_FOUND == num_value ||
            EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_INVALID_EID == num_value ||
            EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_MISSING_EID == num_value ||
            EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_UNDEFINED_ERROR == num_value) {
            obj->value.eim_package_error = num_value;
        } else {
            LOGE("[esipa_json_extractor__transfer_eim_package_request] Unknown eimPackageError: %d", obj->choice);
            return eInvalidFormat;
        }
        break;
    default:
        LOGE("[esipa_json_extractor__transfer_eim_package_request] Unknown TransferEimPackage JSON requestBody CHOICE: %d", obj->choice);
        return eNotSupported;
    }

    if (rc != eOk) {
        LOGE("[esipa_json_extractor__transfer_eim_package_request] Error on parse the JSON requestBody TLV for the %d choice, err %d", obj->choice, rc);
        return eInvalidFormat;
    }

    return eOk;
}

static ErrCode esipa_json_extractor__get_eim_package_response_error(gsma_json_response_header_t* header, enum eim_package_error_from_eim_to_ipa_e* obj) {
    *obj = EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_eim_package_response_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_eim_package_response_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // EID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGD("[esipa_json_extractor__get_eim_package_response_error] No pending eIM Package for the EID.");
                *obj = EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_NO_EIM_PACKAGE_AVAILABLE;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_eim_package_response_error] EID parameter is invalid.");
                *obj = EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_INVALID_EID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MANDATORY_ELEMENT_MISSING_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_eim_package_response_error] Mandatory EID parameter is missing.");
                *obj = EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_MISSING_EID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_eim_package_response_error] No eUICC found with specified EID.");
                *obj = EIM_PACKAGE_ERROR_FROM_EIM_TO_IPA_EID_NOT_FOUND;
            }
        }
    }
    LOGT("[esipa_json_extractor__get_eim_package_response_error] eimPackageError: %d", *obj);

    return eOk;
}

static ErrCode esipa_json_extractor__provide_eim_package_result_response_body(unsigned char* json, uint32_t json_len, provide_eim_package_result_response_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* base64 = NULL;
    uint32_t base64_len = 0;
    int32_t tlv_size = 0;

    /* Extract the JSON requestBody CHOICE */
    if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY, &base64, &base64_len))) {
        LOGD("[esipa_json_extractor__provide_eim_package_result_response_body] %s found", EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY);
        obj->choice = EIM_ACKNOWLEDGEMENTS_CHOICE_PEPRR;
        /* Parse the base64 in place, overwriting the json string buffer */
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__provide_eim_package_result_response_body] base64: ", base64, base64_len);
        if ((tlv_size = base64__decode(base64, base64_len, base64, base64_len)) < 0) {
            LOGE("[esipa_json_extractor__provide_eim_package_result_response_body] Error parsing the base64 string, err %d", tlv_size);
            return eFatal;
        }
        LOG_DATA(eLogTrace, "[esipa_json_extractor__provide_eim_package_result_response_body] ASN1: ", base64, tlv_size);
        /* Extract the TLV data */
        if ((rc = esipa_tlv_extractor__eim_acknowledgements((uint8_t*) base64, (uint32_t) tlv_size, &obj->value.eim_acknowledgements)) != eOk) {
            LOGE("[esipa_json_extractor__provide_eim_package_result_response_body] Error on parse the eimAcknowledgements TLV, err %d", tlv_size);
            return eFatal;
        }
    } else {
        LOGD("[esipa_json_extractor__provide_eim_package_result_response_body] %s not found, setting emptyResponse as choice", EIM_ACKNOWLEDGEMENTS_ESIPA_JSON_KEY);
        obj->choice = EMPTY_RESPONSE_CHOICE_PEPRR;
    }

    return eOk;
}

static ErrCode esipa_json_extractor__provide_eim_package_result_response_error(gsma_json_response_header_t* header, enum provide_eim_package_result_error_e* obj) {
    *obj = PROVIDE_EIM_PKG_RESULT_ERROR_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__provide_eim_package_result_response_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__provide_eim_package_result_response_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // EID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__provide_eim_package_result_response_error] EID parameter is invalid.");
                *obj = PROVIDE_EIM_PKG_RESULT_ERROR_INVALID_EID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MANDATORY_ELEMENT_MISSING_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__provide_eim_package_result_response_error] Mandatory EID parameter is missing.");
                *obj = PROVIDE_EIM_PKG_RESULT_ERROR_MISSING_EID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__provide_eim_package_result_response_error] No eUICC found with specified EID.");
                *obj = PROVIDE_EIM_PKG_RESULT_ERROR_EID_NOT_FOUND;
            }
        }
    }
    LOGT("[esipa_json_extractor__provide_eim_package_result_response_error] provideEimPackageResultError: %d", *obj);

    return eOk;
}
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode esipa_json_extractor__initiate_authentication_response_esipa_ok_body(unsigned char* json, uint32_t json_len, initiate_authentication_ok_esipa_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* json_value = NULL;
    uint32_t json_value_len = 0;
    int32_t tlv_size = 0;

    // euiccCiPKIdentifierToBeUsed
    if ((rc = json_data_extractor__get_string_value(json, json_len, EUICC_CI_PK_IDENTIFIER_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", EUICC_CI_PK_IDENTIFIER_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] euiccCiPKIdentifierToBeUsed base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error parsing the base64 of euiccCiPKIdentifierToBeUsed, err %d", tlv_size);
        return eFatal;
    }
    LOG_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] euiccCiPKIdentifierToBeUsed ASN1: ", json_value, (uint32_t) tlv_size);
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(EUICC_CI_PK_ID, (uint8_t*) json_value, (uint32_t) tlv_size, NULL, obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, sizeof(obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.value), &obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.size)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error extracting the truncated euiccCiPKIdToBeUsed, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] truncated euiccCiPKIdToBeUsed", obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.size);
#else
    if ((rc = tlv_data_extractor__subject_key_identifier(EUICC_CI_PK_ID, (uint8_t*) json_value, (uint32_t) tlv_size, NULL, &obj->euicc_ci_pk_id_to_be_used.subject_key_identifier)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error extracting the euiccCiPKIdToBeUsed, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] euiccCiPKIdToBeUsed", obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.value, sizeof(obj->euicc_ci_pk_id_to_be_used.subject_key_identifier.value));

    // transactionId OPTIONAL
    if (eOk == (rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id))) {
        LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] transactionId", obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size);
        obj->field_is_present.transaction_id = true;
    } else {
        LOGD("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of the transactionId, rc %d", rc);
        obj->field_is_present.transaction_id = false;
    }
#endif

    // serverSigned1
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_SIGNED_1_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", SERVER_SIGNED_1_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverSigned1 base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error parsing the base64 of serverSigned1, err %d", tlv_size);
        return eFatal;
    }
    obj->server_signed_1 = (uint8_t*) json_value;
    obj->server_signed_1_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverSigned1", obj->server_signed_1, obj->server_signed_1_size);

    // serverSignature1
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_SIGNATURE_1_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", SERVER_SIGNATURE_1_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverSignature1 base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error parsing the base64 of serverSignature1, err %d", tlv_size);
        return eFatal;
    }
    obj->server_signature_1 = (uint8_t*) json_value;
    obj->server_signature_1_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverSignature1", obj->server_signature_1, obj->server_signature_1_size);

    // serverCertificate
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_CERTIFICATE_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", SERVER_CERTIFICATE_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverCertificate base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error parsing the base64 of serverCertificate, err %d", tlv_size);
        return eFatal;
    }
    obj->server_certificate = (uint8_t*) json_value;
    obj->server_certificate_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] serverCertificate", obj->server_certificate, obj->server_certificate_size);

#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
    // ctxParams1
    if ((rc = json_data_extractor__get_string_value(json, json_len, CTX_PARAMS_1_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", CTX_PARAMS_1_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] ctxParams1 base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Error parsing the base64 of ctxParams1, err %d", tlv_size);
        return eFatal;
    }
    obj->ctx_params_1_value = (uint8_t*) json_value;
    obj->ctx_params_1_value_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] ctxParams1", obj->ctx_params_1_value, obj->ctx_params_1_value_size);
#else
    // matchingId OPTIONAL
    if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, MATCHING_ID_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        obj->matching_id = (uint8_t*) json_value;
        obj->matching_id_size = (uint8_t) tlv_size;
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] matchingId: ", obj->matching_id, obj->matching_id_size);
        obj->field_is_present.matching_id = true;
    } else {
        LOGD("[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] Can not get the value of %s, rc %d", MATCHING_ID_ESIPA_JSON_KEY, rc);
        obj->field_is_present.matching_id = false;
    }
#endif

    return eOk;
}

static ErrCode esipa_json_extractor__initiate_authentication_response_esipa_error(gsma_json_response_header_t* header, enum initiate_authentication_error_esipa_e* obj) {
    *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // SM-DP+ Address 
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_ADDRESS_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] Invalid SM-DP+ Address.");
                *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_DP_ADDRESS;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_ASSOCIATION_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] SM-DP+ or SM-DS address returned by the RSP Server does not match the expected value.");
                *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_ADDRESS_MISMATCH;
            }
        }
        // Security configuration
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SECURITY_CONFIG_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] None of the proposed Public Key Identifiers is supported by the SM-DP+.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED;
        }
        // Specification Version Number
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SVN_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] The Specification Version Number indicated by the eUICC is not supported by the SM-DP+.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_EUICC_VERSION_NOT_SUPPORTED_BY_DP;
        }
        // SM-DP+ Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] The SM-DP+ has no CERT.DPAuth.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED;
        }
        // SM-DS Address 
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_ADDRESS_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] Invalid SM-DS Address.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_DP_ADDRESS;
        }
        // Security configuration
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_SECURITY_CONFIG_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] None of the proposed Public Key Identifiers is supported by the SM-DS.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED;
        }
        // Specification Version Number
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_SVN_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] The Specification Version Number indicated by the eUICC is not supported by the SM-DS.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_EUICC_VERSION_NOT_SUPPORTED_BY_DP;
        }
        // SM-DP+ Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] The SM-DS has no CERT.DS.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_CI_PK_ID_NOT_SUPPORTED;
        }
        // eIM TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EIM_TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_ASSOCIATION_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] The provided eIM TransactionId is not valid.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_INVALID_EIM_TRANSACTION_ID;
        }
        // SM-DP+
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_ASSOCIATION_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__initiate_authentication_response_esipa_error] SM-DP+ OID in an Activation Code does not match the SM-DP+ OID in the SM-DP+ Certificate");
            *obj = INITIATE_AUTHENTICATION_ERROR_ESIPA_SMDP_OID_MISMATCH;
        }
    }
    LOGT("[esipa_json_extractor__initiate_authentication_response_esipa_error] initiateAuthenticationErrorEsipa: %d", *obj);

    return eOk;
}

static ErrCode esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body(unsigned char* json, uint32_t json_len, authenticate_client_ok_dp_esipa_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* json_value = NULL;
    uint32_t json_value_len = 0;
    int32_t tlv_size = 0;

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    // transactionId OPTIONAL
    if (eOk == (rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id))) {
        LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] transactionId", obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size);
        obj->field_is_present.transaction_id = true;
    } else {
        LOGD("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of the transactionId, rc %d", rc);
        obj->field_is_present.transaction_id = false;
    }
#endif

#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
    // profileMetadata
    if ((rc = json_data_extractor__get_string_value(json, json_len, PROFILE_METADATA_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of %s, rc %d", PROFILE_METADATA_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] profileMetadata base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the base64 of profileMetadata, err %d", tlv_size);
        return eFatal;
    }
    obj->profile_metadata = (uint8_t*) json_value;
    obj->profile_metadata_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] profileMetadata", obj->profile_metadata, obj->profile_metadata_size);
#endif

    // smdpSigned2
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNED_2_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of %s, rc %d", SMDP_SIGNED_2_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] smdpSigned2 base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the base64 of smdpSigned2, err %d", tlv_size);
        return eFatal;
    }
    obj->smdp_signed_2 = (uint8_t*) json_value;
    obj->smdp_signed_2_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] serverSigned1", obj->smdp_signed_2, obj->smdp_signed_2_size);

    // smdpSignature2
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNATURE_2_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of %s, rc %d", SMDP_SIGNATURE_2_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] smdpSignature2 base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the base64 of smdpSignature2, err %d", tlv_size);
        return eFatal;
    }
    obj->smdp_signature_2 = (uint8_t*) json_value;
    obj->smdp_signature_2_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] smdpSignature2", obj->smdp_signature_2, obj->smdp_signature_2_size);

    // smdpCertificate
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_CERTIFICATE_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of %s, rc %d", SMDP_CERTIFICATE_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] smdpCertificate base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the base64 of smdpCertificate, err %d", tlv_size);
        return eFatal;
    }
    obj->smdp_certificate = (uint8_t*) json_value;
    obj->smdp_certificate_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] serverCertificate", obj->smdp_certificate, obj->smdp_certificate_size);

    // hashCc OPTIONAL
    if (eOk == (rc = json_data_extractor__get_string_value(json, json_len, HASH_CC_ESIPA_JSON_KEY, &json_value, &json_value_len))) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] hashCc base64: ", json_value, json_value_len);
        obj->field_is_present.hash_cc = true;
        if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
            LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the base64 of hashCc, err %d", tlv_size);
            return eFatal;
        }
        LOG_DATA(eLogTrace, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] hashCc ASN1: ", json_value, (uint32_t) tlv_size);
        if ((rc = tlv_data_extractor__tlv_value_small_size_copy(HASH_CC, json_value, (uint32_t) tlv_size, NULL, obj->hash_cc.hash, sizeof(obj->hash_cc.hash), NULL)) != eOk) {
            LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error extracting the hashCc, rc %d", rc);
            return rc;
        }
        LOG_DATA(eLogDebug, "[esipa_json_extractor__initiate_authentication_response_esipa_ok_body] hashCc", obj->hash_cc.hash, sizeof(obj->hash_cc.hash));
    } else {
        LOGD("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of the hashCc, rc %d", rc);
        obj->field_is_present.hash_cc = false;
    }

    return eOk;
}

/* This case is not yet defined in the JSON binding */
static ErrCode esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body(unsigned char* json, uint32_t json_len, authenticate_client_ok_ds_esipa_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* json_value = NULL;
    uint32_t json_value_len = 0;
    int32_t tlv_size = 0;

    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }

    // profileDownloadTrigger
    if ((rc = json_data_extractor__get_string_value(json, json_len, PROFILE_DOWNLOAD_TRIGGER_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] Can not get the value of %s, rc %d", PROFILE_DOWNLOAD_TRIGGER_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] profileDownloadTrigger base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] Error parsing the base64 of profileDownloadTrigger, err %d", tlv_size);
        return eFatal;
    }
    LOG_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] profileDownloadTrigger ASN1: ", json_value, tlv_size);
    if ((rc = esipa_tlv_extractor__profile_download_trigger_request((uint8_t*) json_value, (uint32_t) tlv_size, &obj->profile_download_trigger)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_ds_body] Error on parse the profileDownloadTrigger TLV, err %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode esipa_json_extractor__authenticate_client_response_esipa_error(gsma_json_response_header_t* header, enum authenticate_client_error_esipa_e* obj) {
    *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // EUM Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUM_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] EUM Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] EUM Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EUM_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] eUICC Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] eUICC Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] eUICC signature is invalid or serverChallenge is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EUICC_SIGNATURE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, INSUFFICIENT_MEMORY_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] eUICC does not have sufficient space for this Profile.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_INSUFFICIENT_MEMORY;
            }
        }
        // CI Public Key
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, CI_PUBLIC_KEY_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root for the SM-DP+.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_CI_PK_UNKNOWN;
        }
        // Profile
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, NOT_ALLOWED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] Profile has not yet been released.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_NO_ELIGIBLE_PROFILE;
        }
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] The RSP session identified by the TransactionID is unknown.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_INVALID_TRANSACTION_ID;
        }
        // MatchingID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, MATCHING_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] MatchingID (AC_Token or EventID) is refused.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_MATCHING_ID_REFUSED;
        }
        // EID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] EID doesn't match the expected value.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_EID_MISMATCH;
        }
        // Profile Type
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_TYPE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, STOPPED_ON_WARNING_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] No eligible Profile for this eUICC/Device.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_NO_ELIGIBLE_PROFILE;
        }
        // Download order
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, DOWNLOAD_ORDER_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, TTL_EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] The Download order has expired.");
                /* JSON Status code not defined in ASN.1 so will remain as undefined */
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MAX_NUM_OF_RETRIES_EXCEEDED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] The maximum number of retries for the Profile download order has been exceeded.");
                /* JSON Status code not defined in ASN.1 so will remain as undefined */
            }
        }
        // PPR
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PPR_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, NOT_ALLOWED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__authenticate_client_response_esipa_error] The corresponding ES9+'.AuthenticateClient function returned PPR not allowed in RAT.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ESIPA_PPR_NOT_ALLOWED;
        }
    }
    LOGT("[esipa_json_extractor__authenticate_client_response_esipa_error] authenticateClientErrorEsipa: %d", *obj);

    return eOk;
}

static ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa_ok_body(unsigned char* json, uint32_t json_len, get_bound_profile_package_ok_esipa_t* obj) {
    ErrCode rc = eFatal;
    unsigned char* json_value = NULL;
    uint32_t json_value_len = 0;
    int32_t tlv_size = 0;

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[esipa_json_extractor__get_bound_profile_package_response_esipa_ok_body] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }
#endif

    // boundProfilePackage
    if ((rc = json_data_extractor__get_string_value(json, json_len, BOUND_PROFILE_PACKAGE_ESIPA_JSON_KEY, &json_value, &json_value_len)) != eOk) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Can not get the value of %s, rc %d", BOUND_PROFILE_PACKAGE_ESIPA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] boundProfilePackage base64: ", json_value, json_value_len);
    if ((tlv_size = base64__decode(json_value, json_value_len, json_value, json_value_len)) < 0) {
        LOGE("[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] Error parsing the boundProfilePackage of smdpSigned2, err %d", tlv_size);
        return eFatal;
    }
    obj->bound_profile_package = (uint8_t*) json_value;
    obj->bound_profile_package_size = (uint32_t) tlv_size;
    LOG_DATA(eLogDebug, "[esipa_json_extractor__authenticate_client_response_esipa_ok_dp_body] boundProfilePackage", obj->bound_profile_package, obj->bound_profile_package_size);

    return eOk;
}

static ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa_error(gsma_json_response_header_t* header, enum get_bound_profile_package_error_esipa_e* obj) {
    *obj = GET_BPP_ERROR_ESIPA_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_bound_profile_package_response_esipa_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__get_bound_profile_package_response_esipa_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] eUICC signature is invalid.");
            *obj = GET_BPP_ERROR_ESIPA_EUICC_SIGNATURE_INVALID;
        }
        // Profile
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] BPP is not available for a new binding.");
            *obj = GET_BPP_ERROR_ESIPA_BPP_REBINDING_REFUSED;
        }
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] The RSP session identified by the TransactionID is unknown.");
            *obj = GET_BPP_ERROR_ESIPA_INVALID_TRANSACTION_ID;
        }
        // Confirmation Code
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, CONFIRMATION_CODE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MANDATORY_ELEMENT_MISSING_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] Confirmation Code is missing.");
                *obj = GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_MISSING;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] Confirmation Code is refused.");
                *obj = GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_REFUSED;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MAX_NUM_OF_RETRIES_EXCEEDED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] The maximum number of retries for the Confirmation Code has been exceeded.");
                *obj = GET_BPP_ERROR_ESIPA_CONFIRMATION_CODE_RETRIES_EXCEEDED;
            }
        }
        // Download order
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, DOWNLOAD_ORDER_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, TTL_EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] The Download order has expired.");
                *obj = GET_BPP_ERROR_ESIPA_DOWNLOAD_ORDER_EXPIRED;
        }
        // Profile Metadata
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_METADATA_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VALUE_HAS_CHANGED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] The Profile Metadata in Bound Profile Package does not match the Profile Metadata received in ES9+'.AuthenticateClient response.");
                *obj = GET_BPP_ERROR_ESIPA_METADATA_MISMATCH;
        }
    }
    LOGT("[esipa_json_extractor__get_bound_profile_package_response_esipa_error] getBoundProfilePackageErrorEsipa: %d", *obj);

    return eOk;
}

static ErrCode esipa_json_extractor__cancel_session_response_esipa_error(gsma_json_response_header_t* header, enum cancel_session_error_esipa_e* obj) {
    *obj = CANCEL_SESSION_ERROR_ESIPA_UNDEFINED_ERROR; // Default
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__cancel_session_response_esipa_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[esipa_json_extractor__cancel_session_response_esipa_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__cancel_session_response_esipa_error] The RSP session identified by the TransactionID is unknown.");
            *obj = CANCEL_SESSION_ERROR_ESIPA_INVALID_TRANSACTION_ID;
        }
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__cancel_session_response_esipa_error] eUICC signature is invalid.");
            *obj = CANCEL_SESSION_ERROR_ESIPA_EUICC_SIGNATURE_INVALID;
        }
        // SM-DP+
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_ASSOCIATION_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[esipa_json_extractor__cancel_session_response_esipa_error] The provided SM-DP+ OID is invalid.");
            /* JSON Status code not defined in ASN.1 so will remain as undefined */
        }
    }
    LOGT("[esipa_json_extractor__cancel_session_response_esipa_error] cancelSessionError: %d", *obj);

    return eOk;
}
#endif
#endif