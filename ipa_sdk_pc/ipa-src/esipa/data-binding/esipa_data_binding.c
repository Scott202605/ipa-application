/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa_data_binding.h"
#include "esipa_tlv_generator.h"
#include "esipa_tlv_extractor.h"
#ifdef ENABLE_ESIPA_JSON
#include "esipa_json_generator.h"
#include "esipa_json_extractor.h"
#endif
#include "log.h"

int32_t esipa_data_binding__generate_handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const handle_notification_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__handle_notification_esipa(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__handle_notification_esipa(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_handle_notification_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const transfer_eim_package_response_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__transfer_eim_package_response(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__transfer_eim_package_response(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_transfer_eim_package_response] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_eim_package_request_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__get_eim_package_request(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__get_eim_package_request(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_get_eim_package_request] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const provide_eim_package_result_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__provide_eim_package_result(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__provide_eim_package_result(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_provide_eim_package_result] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
int32_t esipa_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__initiate_authentication_request(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__initiate_authentication_request(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_initiate_authentication_request] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__authenticate_client_request_esipa(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__authenticate_client_request_esipa(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_authenticate_client_request_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const cancel_session_request_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__cancel_session_request_esipa(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__cancel_session_request_esipa(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_cancel_session_request_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}

int32_t esipa_data_binding__generate_get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_bound_profile_package_request_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_generator__get_bound_profile_package_request_esipa(buffer, buffer_size, 0, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_generator__get_bound_profile_package_request_esipa(buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__generate_get_bound_profile_package_request_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return -eNotSupported;
    }
}
#endif

ErrCode esipa_data_binding__extract_transfer_eim_package_request(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, transfer_eim_package_request_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__transfer_eim_package_request(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__transfer_eim_package_request((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_transfer_eim_package_request] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

ErrCode esipa_data_binding__extract_get_eim_package_response(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_eim_package_response_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__get_eim_package_response(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__get_eim_package_response((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_get_eim_package_response] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

ErrCode esipa_data_binding__extract_provide_eim_package_result_response(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, provide_eim_package_result_response_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__provide_eim_package_result_response(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__provide_eim_package_result_response((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_provide_eim_package_result_response] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
ErrCode esipa_data_binding__extract_initiate_authentication_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__initiate_authentication_response_esipa(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__initiate_authentication_response_esipa((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_initiate_authentication_response_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

ErrCode esipa_data_binding__extract_authenticate_client_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__authenticate_client_response_esipa(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__authenticate_client_response_esipa((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_authenticate_client_response_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

ErrCode esipa_data_binding__extract_get_bound_profile_package_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_bound_profile_package_response_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__get_bound_profile_package_response_esipa(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__get_bound_profile_package_response_esipa((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_get_bound_profile_package_response_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}

ErrCode esipa_data_binding__extract_cancel_session_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, cancel_session_response_esipa_t* obj) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__cancel_session_response_esipa(buffer, buffer_size, obj);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__cancel_session_response_esipa((unsigned char*) buffer, buffer_size, obj);
#endif
    default:
        LOGE("[esipa_data_binding__extract_cancel_session_response_esipa] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}
#endif

ErrCode esipa_data_binding__get_esipa_message_from_eim_to_ipa_choice(const uint8_t* message, const uint32_t message_size, const gsma_data_binding_t data_binding, esipa_message_from_ipa_to_eim_choice_t last_message_sent, esipa_message_from_eim_to_ipa_choice_t* result) {
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        return esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice(message, message_size, result);
#ifdef ENABLE_ESIPA_JSON
    case JSON_DATA_BINDING:
        return esipa_json_extractor__esipa_message_from_eim_to_ipa_choice((unsigned char*) message, message_size, last_message_sent, result);
#endif
    default:
        LOGE("[esipa_data_binding__get_esipa_message_from_eim_to_ipa_choice] data binding (%u) not supported by the ESipa interface", data_binding);
        return eNotSupported;
    }
}
