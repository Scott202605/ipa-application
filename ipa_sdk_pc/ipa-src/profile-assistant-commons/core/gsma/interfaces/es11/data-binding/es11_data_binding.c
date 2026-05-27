/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es11_data_binding.h"
#include "es9_data_binding.h"
#include "es11_json_extractor.h"
#include "log.h"

int32_t es11_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_t* obj) {
    return es9_data_binding__generate_initiate_authentication_request(buffer, buffer_size, data_binding, obj);
}

int32_t es11_data_binding__generate_authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_t* obj) {
    return es9_data_binding__generate_authenticate_client_request(buffer, buffer_size, data_binding, obj);
}

ErrCode es11_data_binding__extract_initiate_authentication_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_t* obj) {
    return es9_data_binding__extract_initiate_authentication_response(buffer, buffer_size, data_binding, obj);
}

ErrCode es11_data_binding__extract_authenticate_client_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_es11_t* obj) {
    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es11_json_extractor__authenticate_client_response(buffer, buffer_size, obj);
    default:
        LOGE("[es11_data_binding__extract_authenticate_client_response] data binding (%u) not supported by the ES11 interface", data_binding);
        return eNotSupported;
    }
}

ErrCode es11_data_binding__extract_next_event_entry(authenticate_client_response_es11_t* response, const gsma_data_binding_t data_binding, event_entry_t* obj) {
    if (AUTHENTICATE_CLIENT_RESPONSE_ES11_OK != response->choice) {
        LOGE("[es11_data_binding__extract_next_event_entry] The AuthenticateClientResponseEs11 is not a authenticateClientOk");
        return eBadArg;
    }

    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es11_json_extractor__get_next_event_entry(&response->value.ok.event_entries.json_list_handler, obj);
    default:
        LOGE("[es11_data_binding__extract_next_event_entry] data binding (%u) not supported by the ES11 interface", data_binding);
        return eNotSupported;
    }
}


ErrCode es11_data_binding__extract_event_entry_list_size(authenticate_client_response_es11_t* response, const gsma_data_binding_t data_binding, uint32_t* list_size) {
    if (AUTHENTICATE_CLIENT_RESPONSE_ES11_OK != response->choice) {
        LOGE("[es11_data_binding__extract_event_entry_list_size] The AuthenticateClientResponseEs11 is not a authenticateClientOk");
        return eBadArg;
    }

    switch (data_binding)
    {
    case JSON_DATA_BINDING:
        return es11_json_extractor__get_event_entry_list_size(&response->value.ok.event_entries.json_list_handler, list_size);
    default:
        LOGE("[es11_data_binding__extract_event_entry_list_size] data binding (%u) not supported by the ES11 interface", data_binding);
        return eNotSupported;
    }
}
