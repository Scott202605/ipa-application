/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es11.h"
#include "http_gsma.h"
#include "network.h"
#include "es11_data_binding.h"
#include "memory_manager.h"
#include "log.h"

#define ES11_DEFAULT_DATA_BINDING JSON_DATA_BINDING

void es11__ctor(es11_t * const es11) {
    es11->data_binding = ES11_DEFAULT_DATA_BINDING;
}

void es11__set_json_data_binding(es11_t * const es11) {
    es11->data_binding = JSON_DATA_BINDING;
}

ErrCode es11__initiate_authentication(es11_t * const es11, const char* smds_address, const initiate_authentication_request_t* request, initiate_authentication_response_t* response) {
    ErrCode rc;
    unsigned char* request_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smds_address) {
        LOGE("[es11__initiate_authentication] The SMDS Address is null");
        return eBadArg;
    }
    if (!request) {
        LOGE("[es11__initiate_authentication] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es11__initiate_authentication] The response object is null");
        return eBadArg;
    }

    /* Generate the HTTP request Body */
    if ((request_body_size = es11_data_binding__generate_initiate_authentication_request(NULL, 0, es11->data_binding, request)) < 0) {
        LOGE("[es11__initiate_authentication] Error calculating the size of the InitiateAuthenticationRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es11__initiate_authentication] Error allocating data for the InitiateAuthenticationRequest");
        return eNoMem;
    }
    if ((request_body_size = es11_data_binding__generate_initiate_authentication_request(request_body, request_body_size, es11->data_binding, request)) < 0) {
        LOGE("[es11__initiate_authentication] Error writting the InitiateAuthenticationRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES11.InitiateAuthentication to the SMDS '%s'", smds_address);
    rc = http_gsma__send_request(smds_address, INIT_AUTH_PATH, es11->data_binding, &request_body, (uint32_t*) &request_body_size, (unsigned char**) &response->context, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk || !response->context) {
        LOGE("[es11__initiate_authentication] Error sending the HTTP request, rc %d", rc);
        return rc;
    }

    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es11__initiate_authentication] HTTP request failed, status code %d", http_status_code);
        M_free(response->context);
        response->context = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    if ((rc = es11_data_binding__extract_initiate_authentication_response((unsigned char*) response->context, response_body_size, es11->data_binding, response)) != eOk) {
        LOGE("[es11__initiate_authentication] Error extracting data from the InitiateAuthenticationResponse, rc %d", rc);
        es11__free_initiate_authentication_response(response);
        return rc;
    }

    return eOk;
}

ErrCode es11__authenticate_client(es11_t * const es11, const char* smds_address, const authenticate_client_request_t* request, authenticate_client_response_es11_t* response)  {
    ErrCode rc;
    unsigned char* request_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smds_address) {
        LOGE("[es11__authenticate_client] The SMDS Address is null");
        return eBadArg;
    }
    if (!request) {
        LOGE("[es11__authenticate_client] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es11__authenticate_client] The response object is null");
        return eBadArg;
    }

    /* Generate the HTTP request Body */
    if ((request_body_size = es11_data_binding__generate_authenticate_client_request(NULL, 0, es11->data_binding, request)) < 0) {
        LOGE("[es11__authenticate_client] Error calculating the size of the AuthenticateClientRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es11__authenticate_client] Error allocating data for the AuthenticateClientRequest");
        return eNoMem;
    }
    if ((request_body_size = es11_data_binding__generate_authenticate_client_request(request_body, request_body_size, es11->data_binding, request)) < 0) {
        LOGE("[es11__authenticate_client] Error writting the AuthenticateClientRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES11.AuthenticateClient to the SMDS '%s'", smds_address);
    rc = http_gsma__send_request(smds_address, AUTH_CLIENT_PATH, es11->data_binding, &request_body, (uint32_t*) &request_body_size, (unsigned char**) &response->context, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk || !response->context) {
        LOGE("[es11__authenticate_client] Error sending the HTTP request, rc %d", rc);
        return rc;
    }

    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es11__authenticate_client] HTTP request failed, status code %d", http_status_code);
        M_free(response->context);
        response->context = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    if ((rc = es11_data_binding__extract_authenticate_client_response((unsigned char*) response->context, response_body_size, es11->data_binding, response)) != eOk) {
        LOGE("[es11__authenticate_client] Error extracting data from the AuthenticateClientResponseEs11, rc %d", rc);
        es11__free_authenticate_client_response(response);
        return rc;
    }

    return eOk;
}

ErrCode es11__get_next_event_entry(es11_t * const es11, authenticate_client_response_es11_t* response, event_entry_t* event_entry) {
    return es11_data_binding__extract_next_event_entry(response, es11->data_binding, event_entry);
}

ErrCode es11__get_event_entry_list_size(es11_t * const es11, authenticate_client_response_es11_t* response, uint32_t* list_size) {
    return es11_data_binding__extract_event_entry_list_size(response, es11->data_binding, list_size);
}

void es11__free_initiate_authentication_response(initiate_authentication_response_t* obj) {
    M_free(obj->context);
    memset(obj, 0, sizeof(initiate_authentication_response_t));
}

void es11__free_authenticate_client_response(authenticate_client_response_es11_t* obj) {
    M_free(obj->context);
    memset(obj, 0, sizeof(authenticate_client_response_es11_t));
}
