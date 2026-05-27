/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es9.h"
#include "log.h"
#include "memory_manager.h"
#include "http_gsma.h"
#include "network.h"
#include "es9_data_binding.h"

#define ES9_DEFAULT_DATA_BINDING JSON_DATA_BINDING

void es9__ctor(es9_t * const es9) {
    es9->data_binding = ES9_DEFAULT_DATA_BINDING;
}

void es9__set_json_data_binding(es9_t * const es9) {
    es9->data_binding = JSON_DATA_BINDING;
}

ErrCode es9__initiate_authentication(es9_t * const es9, const char* smdp_address, const initiate_authentication_request_t* request, initiate_authentication_response_t* response) {
    ErrCode rc;
    unsigned char* request_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smdp_address) {
        LOGE("[es9__initiate_authentication] The SMDP+ Address is null");
        return eBadArg;
    }
    if (!request) {
        LOGE("[es9__initiate_authentication] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es9__initiate_authentication] The response object is null");
        return eBadArg;
    }

    /* Generate the HTTP request Body */
    if ((request_body_size = es9_data_binding__generate_initiate_authentication_request(NULL, 0, es9->data_binding, request)) < 0) {
        LOGE("[es9__initiate_authentication] Error calculating the size of the InitiateAuthenticationRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es9__initiate_authentication] Error allocating data for the InitiateAuthenticationRequest");
        return eNoMem;
    }
    if ((request_body_size = es9_data_binding__generate_initiate_authentication_request(request_body, request_body_size, es9->data_binding, request)) < 0) {
        LOGE("[es9__initiate_authentication] Error writing the InitiateAuthenticationRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES9.InitiateAuthentication to the SMDP+ '%s'", smdp_address);
    rc = http_gsma__send_request(smdp_address, INIT_AUTH_PATH, es9->data_binding, &request_body, (uint32_t*) &request_body_size, (unsigned char**) &response->context, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk || !response->context) {
        LOGE("[es9__initiate_authentication] Error sending the HTTP request, rc %d", rc);
        return rc;
    }

    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es9__initiate_authentication] HTTP request failed, status code %d", http_status_code);
        M_free(response->context);
        response->context = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    if ((rc = es9_data_binding__extract_initiate_authentication_response((unsigned char*) response->context, response_body_size, es9->data_binding, response)) != eOk) {
        LOGE("[es9__initiate_authentication] Error extracting data from the InitiateAuthenticationResponse, rc %d", rc);
        es9__free_initiate_authentication_response(response);
        return rc;
    }

    return eOk;
}

ErrCode es9__authenticate_client(es9_t * const es9, const char* smdp_address, const authenticate_client_request_t* request, authenticate_client_response_es9_t* response) {
    ErrCode rc;
    unsigned char* request_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smdp_address) {
        LOGE("[es9__authenticate_client] The SMDP+ Address is null");
        return eBadArg;
    }
    if (!request) {
        LOGE("[es9__authenticate_client] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es9__authenticate_client] The response object is null");
        return eBadArg;
    }
    /* Generate the HTTP request Body */
    if ((request_body_size = es9_data_binding__generate_authenticate_client_request(NULL, 0, es9->data_binding, request)) < 0) {
        LOGE("[es9__authenticate_client] Error generating the AuthenticateClientRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es9__authenticate_client] Error allocating data for the AuthenticateClientRequest");
        return eNoMem;
    }
    if ((request_body_size = es9_data_binding__generate_authenticate_client_request(request_body, request_body_size, es9->data_binding, request)) < 0) {
        LOGE("[es9__authenticate_client] Error writing the AuthenticateClientRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES9.AuthenticateClient to the SMDP+ '%s'", smdp_address);
    rc = http_gsma__send_request(smdp_address, AUTH_CLIENT_PATH, es9->data_binding, &request_body, (uint32_t*) &request_body_size, (unsigned char**) &response->context, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk || !response->context) {
        LOGE("[es9__authenticate_client] Error sending the HTTP request, rc %d", rc);
        return rc;
    }
    
    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es9__authenticate_client] HTTP request failed, status code %d", http_status_code);
        M_free(response->context);
        response->context = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    if ((rc = es9_data_binding__extract_authenticate_client_response((unsigned char*) response->context, response_body_size, es9->data_binding, response)) != eOk) {
        LOGE("[es9__authenticate_client] Error extracting data from the AuthenticateClientResponseEs9, rc %d", rc);
        es9__free_authenticate_client_response(response);
        return rc;
    }
    
    return eOk;
}

ErrCode es9__get_bound_profile_package(es9_t * const es9, const char* smdp_address, const get_bound_profile_package_request_t* request,  get_bound_profile_package_response_t* response) {
    ErrCode rc;
    unsigned char* request_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smdp_address) {
        LOGE("[es9__get_bound_profile_package] The SMDP+ Address is null");
        return eBadArg;
    }
    if (!request) {
        LOGE("[es9__get_bound_profile_package] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es9__get_bound_profile_package] The response object is null");
        return eBadArg;
    }
    /* Generate the HTTP request Body */
    if ((request_body_size = es9_data_binding__generate_get_bound_profile_package_request(NULL, 0, es9->data_binding, request)) < 0) {
        LOGE("[es9__get_bound_profile_package] Error generating the GetBoundProfilePackageRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es9__get_bound_profile_package] Error allocating data for the GetBoundProfilePackageRequest");
        return eNoMem;
    }
    if ((request_body_size = es9_data_binding__generate_get_bound_profile_package_request(request_body, request_body_size, es9->data_binding, request)) < 0) {
        LOGE("[es9__get_bound_profile_package] Error writing the GetBoundProfilePackageRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES9.GetBoundProfilePackage to the SMDP+ '%s'", smdp_address);
    rc = http_gsma__send_request(smdp_address, GET_BPP_PATH, es9->data_binding, &request_body, (uint32_t*) &request_body_size, (unsigned char**) &response->context, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk || !response->context) {
        LOGE("[es9__get_bound_profile_package] network__send_https_request failed, rc %d", rc);
        return rc;
    }

    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es9__get_bound_profile_package] HTTP request failed, HTTP status code %d", http_status_code);
        M_free(response->context);
        response->context = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    if ((rc = es9_data_binding__extract_get_bound_profile_package_response((unsigned char*) response->context, response_body_size, es9->data_binding, response)) != eOk) {
        LOGE("[es9__get_bound_profile_package] Error extracting data from the GetBoundProfilePackageResponse, rc %d", rc);
        es9__free_get_bound_profile_package_response(response);
        return rc;
    }
    
    return eOk;
}

ErrCode es9__handle_notification(es9_t * const es9, const char* smdp_address, const uint8_t* pending_notification, const size_t pending_notification_size) {
    ErrCode rc;
    unsigned char* request_body;
    unsigned char* response_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    if (!smdp_address || !pending_notification || pending_notification_size == 0) {
        return eBadArg;
    }

    if ((request_body_size = es9_data_binding__generate_handle_notification_request(NULL, 0, es9->data_binding, pending_notification, pending_notification_size)) < 0) {
        LOGE("[es9__handle_notification] es9_data_binding__generate_handle_notification_request failed, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es9__handle_notification] Error allocating data for the HandleNotificationRequest");
        return eNoMem;
    }
    if ((request_body_size = es9_data_binding__generate_handle_notification_request(request_body, request_body_size, es9->data_binding, pending_notification, pending_notification_size)) < 0) {
        LOGE("[es9__handle_notification] Error writing the HandleNotificationRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }
    LOGI("ES9.HandleNotification to the SMDP+ '%s'", smdp_address);

    //Send the install notification notification
    rc = http_gsma__send_request(smdp_address, HANDLE_NOTIFICATION_PATH, es9->data_binding, &request_body, (uint32_t*) &request_body_size, &response_body, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk) {
        LOGE("[es9__handle_notification] network__send_https_request failed, rc %d", rc);
        return rc;
    }

    M_free(response_body);
    response_body = NULL;
    response_body_size = 0;

    if (http_status_code != HTTP_STATUS_CODE_OK && http_status_code != HTTP_STATUS_CODE_NO_CONTENT) {
        LOGE("[es9__handle_notification] HTTP request failed, HTTP status code %d", http_status_code);
        return eFatal;
    }

    return eOk;
}

ErrCode es9__cancel_session(es9_t * const es9, const char* smdp_address, const cancel_session_request_es9_t* request, cancel_session_response_es9_t* response) {
    ErrCode rc;
    unsigned char* request_body;
    unsigned char* response_body;
    int32_t request_body_size;
    uint32_t response_body_size;
    int http_status_code;

    /* Check input parameters */
    if (!smdp_address) {
        LOGE("[es9__cancel_session] The SMDP+ Address is null");
        return eBadArg;
    }    
    if (!request) {
        LOGE("[es9__cancel_session] The request object is null");
        return eBadArg;
    }
    if (!response) {
        LOGE("[es9__cancel_session] The response object is null");
        return eBadArg;
    }

    /* Generate the HTTP request Body */
    if ((request_body_size = es9_data_binding__generate_cancel_session_request(NULL, 0, es9->data_binding, request)) < 0) {
        LOGE("[es9__cancel_session] Error generating the CancelSessionRequest, err %d", request_body_size);
        return eFatal;
    }
    request_body = M_malloc(request_body_size);
    if (!request_body) {
        LOGE("[es9__cancel_session] Error allocating data for the CancelSessionRequest");
        return eNoMem;
    }
    if ((request_body_size = es9_data_binding__generate_cancel_session_request(request_body, request_body_size, es9->data_binding, request)) < 0) {
        LOGE("[es9__cancel_session] Error writing the CancelSessionRequest to the allocated buffer, err %d", request_body_size);
        M_free(request_body);
        return eFatal;
    }

    /* Send the HTTP request */
    LOGI("ES9.CancelSession to the SMDP+ '%s'", smdp_address);
    rc = http_gsma__send_request(smdp_address, CANCEL_SESSION_PATH, es9->data_binding, &request_body, (uint32_t*) &request_body_size, &response_body, &response_body_size, &http_status_code);
    M_free(request_body);
    request_body = NULL;
    request_body_size = 0;
    if (rc != eOk) {
        LOGE("[es9__cancel_session] HTTP send request function failed, rc %d", rc);
        return rc;
    }

    /* Check HTTP response status code */
    if (http_status_code != HTTP_STATUS_CODE_OK) {
        LOGE("[es9__cancel_session] HTTP request failed, HTTP status code %d", http_status_code);
        M_free(response_body);
        response_body = NULL;
        return eFatal;
    }

    /* Extract the HTTP response body */
    rc = es9_data_binding__extract_cancel_session_response(response_body, response_body_size, es9->data_binding, response);
    M_free(response_body);
    response_body = NULL;
    if (rc != eOk) {
        LOGE("[es9__authenticate_client] Error extracting data from the CancelSessionResponse, rc %d", rc);
    }

    return rc;
}

void es9__free_initiate_authentication_response(initiate_authentication_response_t* obj) {
    M_free(obj->context);
    memset(obj, 0, sizeof(initiate_authentication_response_t));
}

void es9__free_authenticate_client_response(authenticate_client_response_es9_t* obj) {
    M_free(obj->context);
    memset(obj, 0, sizeof(authenticate_client_response_es9_t));
}

void es9__free_get_bound_profile_package_response(get_bound_profile_package_response_t* obj) {
    M_free(obj->context);
    memset(obj, 0, sizeof(get_bound_profile_package_response_t));
}
