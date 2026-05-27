/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "http_gsma.h"
#include "network.h"
#include "memory_manager.h"
#include "log.h"

#define HTTP_GSMA_ASN1_PATH "/gsma/rsp2/asn1"

#define HTTP_USER_AGENT_HEADER          "User-Agent: gsma-rsp-lpad"
#define HTTP_X_ADMIN_PROTOCOL_HEADER    "X-Admin-Protocol: gsma/rsp/v2.2.2"
#define HTTP_CONTENT_TYPE_JSON_HEADER   "Content-Type: application/json"
#define HTTP_CONTENT_TYPE_ASN1_HEADER   "Content-Type: application/x-gsma-rsp-asn1"
#define HTTP__GSMA_TIMEOUT   120 // In seconds
ErrCode http_gsma__send_request(const char* fqdn, const char* path, const gsma_data_binding_t data_binding, unsigned char** request_body, uint32_t* request_body_size, unsigned char** response_body, uint32_t* response_body_size, int* http_status_code) {
    ErrCode rc;
    // Create the headers list
    const char* http_headers_list[] = { HTTP_USER_AGENT_HEADER, HTTP_X_ADMIN_PROTOCOL_HEADER, ASN1_DATA_BINDING == data_binding ? HTTP_CONTENT_TYPE_ASN1_HEADER : HTTP_CONTENT_TYPE_JSON_HEADER };
    // Change the endpoint path in case of ASN.1 data binding
    const char* real_path = ASN1_DATA_BINDING == data_binding ? HTTP_GSMA_ASN1_PATH : path;
    
    /* Check input parameters */
    if (!fqdn) {
        LOGE("[http_gsma__send_request] The FQDN is null");
        return eBadArg;
    }
    if (!path) {
        LOGE("[http_gsma__send_request] The HTTP Path is null");
        return eBadArg;
    }
    if (!(*request_body) || *request_body_size == 0) {
        LOGE("[http_gsma__send_request] The HTTP Request Body is empty/null");
        return eBadArg;
    }

    /* Initialize output parameters */
    *response_body = NULL;
    *response_body_size = 0;
    *http_status_code = 0;

    /* Log request data */
    LOGD("[http_gsma__send_request] Sending an HTTP request to %s%s", fqdn, real_path);
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        LOG_DATA(eLogDebug, "[http_gsma__send_request] Request body", *request_body, *request_body_size);
        break;
    case JSON_DATA_BINDING:
        LOG_UTF8_DATA(eLogDebug, "[http_gsma__send_request] Request body\n", *request_body, *request_body_size);
        break;
    default:
        LOGE("[http_gsma__send_request] Unknown request data binding %d", data_binding);
        return eFatal;
    }

    /* Send the HTTP POST request */
    if ((rc = network__send_https_post_request(fqdn, real_path, http_headers_list, sizeof(http_headers_list) / sizeof(char*), request_body, request_body_size, response_body, response_body_size, http_status_code,HTTP__GSMA_TIMEOUT)) != eOk) {
        LOGE("[http_gsma__send_request] Error on send the GSMA HTTP POST request, rc %d", rc);
        return rc;
    }

    /* Log response data */
    LOGD("[http_gsma__send_request] HTTP Status code %d", *http_status_code);
    // Should we check the "Content-type" header in the HTTP response?
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
        LOG_DATA(eLogDebug, "[http_gsma__send_request] Response body", *response_body, *response_body_size);
        break;
    case JSON_DATA_BINDING:
        LOG_UTF8_DATA(eLogDebug, "[http_gsma__send_request] Response body\n", *response_body, *response_body_size);
        break;
    default:
        LOGE("[http_gsma__send_request] Unknown response data binding %d", data_binding);
        M_free(*response_body);
        *response_body = NULL;
        *response_body_size = 0;
        return eFatal;
    }

    // Should we check the "X-Admin-Protocol" header in the HTTP response?

    return eOk;
}
