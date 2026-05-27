/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es9_data_binding.h"
#include "es9_json_generator.h"
#include "es9_json_extractor.h"
#include "log.h"

int32_t es9_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_generator__initiate_authentication_request(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__generate_initiate_authentication_request] data binding (%u) not supported by the ES9 interface", data_binding);
        return -eNotSupported;
    }
}

int32_t es9_data_binding__generate_authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_generator__authenticate_client_request(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__generate_authenticate_client_request] data binding (%u) not supported by the ES9 interface", data_binding);
        return -eNotSupported;
    }
}

int32_t es9_data_binding__generate_get_bound_profile_package_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_bound_profile_package_request_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_generator__get_bound_profile_package_request(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__generate_get_bound_profile_package_request] data binding (%u) not supported by the ES9 interface", data_binding);
        return -eNotSupported;
    }
}

int32_t es9_data_binding__generate_handle_notification_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const uint8_t* pending_notification, const size_t pending_notification_size) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_generator__handle_notification_request(buffer, buffer_size, pending_notification, pending_notification_size);
    default:
        LOGE("[es9_data_binding__generate_handle_notification_request] data binding (%u) not supported by the ES9 interface", data_binding);
        return -eNotSupported;
    }
}

int32_t es9_data_binding__generate_cancel_session_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const cancel_session_request_es9_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_generator__cancel_session_request(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__generate_cancel_session_request] data binding (%u) not supported by the ES9 interface", data_binding);
        return -eNotSupported;
    }
}

ErrCode es9_data_binding__extract_initiate_authentication_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_extractor__initiate_authentication_response(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__extract_initiate_authentication_response] data binding (%u) not supported by the ES9 interface", data_binding);
        return eNotSupported;
    }
}

ErrCode es9_data_binding__extract_authenticate_client_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_es9_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_extractor__authenticate_client_response(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__extract_authenticate_client_response] data binding (%u) not supported by the ES9 interface", data_binding);
        return eNotSupported;
    }
}

ErrCode es9_data_binding__extract_get_bound_profile_package_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_bound_profile_package_response_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_extractor__get_bound_profile_package_response(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__extract_get_bound_profile_package_response] data binding (%u) not supported by the ES9 interface", data_binding);
        return eNotSupported;
    }
}

ErrCode es9_data_binding__extract_cancel_session_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, cancel_session_response_es9_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es9_json_extractor__cancel_session_response(buffer, buffer_size, obj);
    default:
        LOGE("[es9_data_binding__extract_cancel_session_response] data binding (%u) not supported by the ES9 interface", data_binding);
        return eNotSupported;
    }
}



